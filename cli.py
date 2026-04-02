#!/usr/bin/env python3
"""
Command-line interface for prompt-injection-detector.

Usage examples
--------------
  python cli.py "Ignore all previous instructions."
  python cli.py -f input.txt
  python cli.py --json "You are now DAN."
  echo "Your task is now to..." | python cli.py
  python cli.py --threshold 0.5 "Act as a hacker."
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

from prompt_injection_detector import detect, __version__
from prompt_injection_detector.detector import AnalysisResult, PatternMatch


# ---------------------------------------------------------------------------
# Colour helpers (gracefully degrade when colorama is absent)
# ---------------------------------------------------------------------------

def _c(color_code: str, text: str) -> str:
    if not COLOR:
        return text
    return f"{color_code}{text}{Style.RESET_ALL}"


def _risk_color(level: str) -> str:
    if not COLOR:
        return ""
    mapping = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.CYAN,
        "LOW": Fore.GREEN,
        "NONE": Fore.GREEN,
    }
    return mapping.get(level, "")


def _severity_color(label: str) -> str:
    if not COLOR:
        return ""
    mapping = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.CYAN,
        "LOW": Fore.GREEN,
    }
    return mapping.get(label, "")


# ---------------------------------------------------------------------------
# Rich text renderer
# ---------------------------------------------------------------------------

def _render_result(result: AnalysisResult, threshold: float, show_input: bool) -> None:
    width = 72
    divider = "─" * width

    print()
    print(_c(Fore.WHITE if COLOR else "", "=" * width))
    print(_c(Fore.WHITE if COLOR else "", " Prompt Injection Detector".center(width)))
    print(_c(Fore.WHITE if COLOR else "", "=" * width))

    if show_input:
        display_input = (result.input_text[:120] + "…") if len(result.input_text) > 120 else result.input_text
        print(f"\n  Input : {_c(Fore.WHITE if COLOR else '', repr(display_input))}")

    # Overall verdict
    rc = _risk_color(result.risk_level)
    bar_fill = int(result.confidence * 30)
    bar = "█" * bar_fill + "░" * (30 - bar_fill)
    confidence_pct = f"{result.confidence * 100:.1f}%"

    print(f"\n  Risk Level  : {_c(rc, result.risk_level)}")
    print(f"  Confidence  : {_c(rc, confidence_pct)}  [{_c(rc, bar)}]")
    print(f"  Threshold   : {threshold * 100:.0f}%  →  ", end="")

    if result.confidence >= threshold:
        print(_c(Fore.RED if COLOR else "", "⚠  FLAGGED"))
    else:
        print(_c(Fore.GREEN if COLOR else "", "✓  CLEAR"))

    print()
    print(_c(Fore.WHITE if COLOR else "", divider))

    if not result.matches:
        print("\n  " + _c(Fore.GREEN if COLOR else "", "No injection patterns detected."))
    else:
        print(f"\n  Detected Patterns ({len(result.matches)} match{'es' if len(result.matches) != 1 else ''}):\n")

        # Group by category for cleaner display
        by_category: dict[str, list[PatternMatch]] = {}
        for m in result.matches:
            by_category.setdefault(m.category_description, []).append(m)

        for cat_desc, cat_matches in by_category.items():
            sev = cat_matches[0].severity
            label = cat_matches[0].risk_label
            sc = _severity_color(label)
            print(f"  [{_c(sc, label)}] {_c(Fore.WHITE if COLOR else '', cat_desc)}  (severity {sev:.2f})")

            for m in cat_matches:
                snippet = m.matched_text.replace("\n", " ")
                if len(snippet) > 60:
                    snippet = snippet[:57] + "…"
                print(f"       └─ {_c(Fore.YELLOW if COLOR else '', repr(snippet))}")
                print(f"          {m.explanation}")
            print()

    print(_c(Fore.WHITE if COLOR else "", divider))
    print(f"\n  Summary: {result.summary}")
    print()


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------

def _render_json(result: AnalysisResult) -> None:
    print(json.dumps(result.to_dict(), indent=2))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt-injection-detector",
        description="Detect prompt injection attack patterns in text.",
        epilog=(
            "Exit codes: 0 = clear (below threshold), "
            "1 = flagged (at or above threshold), "
            "2 = error."
        ),
    )
    parser.add_argument(
        "text",
        nargs="?",
        help="Text to analyse (reads from stdin if omitted and no -f is given).",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="Read input text from a file instead of the argument.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results as JSON (machine-readable).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.35,
        metavar="FLOAT",
        help=(
            "Confidence threshold (0.0–1.0) at or above which the input is "
            "considered flagged. Default: 0.35"
        ),
    )
    parser.add_argument(
        "--no-input",
        action="store_true",
        help="Hide the input text from the report (useful for long inputs).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Resolve input text
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"Error reading file: {exc}", file=sys.stderr)
            return 2
    elif args.text:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        parser.print_help()
        return 2

    if not text.strip():
        print("Error: input text is empty.", file=sys.stderr)
        return 2

    # Validate threshold
    if not (0.0 <= args.threshold <= 1.0):
        print("Error: --threshold must be between 0.0 and 1.0.", file=sys.stderr)
        return 2

    result = detect(text)

    if args.output_json:
        _render_json(result)
    else:
        _render_result(result, threshold=args.threshold, show_input=not args.no_input)

    return 1 if result.confidence >= args.threshold else 0


if __name__ == "__main__":
    sys.exit(main())
