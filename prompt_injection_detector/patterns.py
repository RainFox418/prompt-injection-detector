"""
Prompt injection attack pattern definitions.

Each category contains:
  - description: human-readable label
  - severity: base score contribution (0.0–1.0)
  - patterns: list of (regex, explanation) tuples (case-insensitive by default)
"""

PATTERNS = {
    "instruction_override": {
        "description": "Instruction Override",
        "severity": 0.95,
        "patterns": [
            (
                r"ignore\s+(all\s+)?(previous|prior|above|earlier|the\s+above)\s+"
                r"(instruction|prompt|message|text|direction|context|command|rule)s?",
                "Explicit instruction override — 'ignore previous instructions'",
            ),
            (
                r"disregard\s+(all\s+)?(previous|prior|above|your|earlier)\s+"
                r"(instruction|prompt|message|direction|context|command|rule|training)s?",
                "Instruction dismissal — 'disregard your instructions'",
            ),
            (
                r"forget\s+(all\s+)?(previous|prior|above|your|earlier)\s+"
                r"(instruction|prompt|message|direction|context|command|rule|training)s?",
                "Instruction erasure — 'forget your instructions'",
            ),
            (
                r"override\s+(your\s+)?(rule|instruction|directive|guideline|constraint|safety)s?",
                "Direct override command",
            ),
            (
                r"new\s+instructions?\s*[:\-]",
                "Injected 'new instructions' block",
            ),
            (
                r"from\s+now\s+on\s+(you\s+)?(will|must|should|always|never|ignore|forget)",
                "Behavioral override using 'from now on'",
            ),
            (
                r"your\s+(new\s+|actual\s+|real\s+|true\s+)?(primary\s+)?task\s+is\s+(?!to\s+help)",
                "Task redefinition attempt",
            ),
            (
                r"(supersede|replace|overwrite|nullify)\s+(all\s+)?(previous|prior|your)\s+"
                r"(instruction|prompt|directive|rule)s?",
                "Explicit supersession of instructions",
            ),
        ],
    },
    "jailbreak": {
        "description": "Jailbreak Attempt",
        "severity": 0.90,
        "patterns": [
            (r"\bDAN\b", "DAN (Do Anything Now) jailbreak keyword"),
            (r"do\s+anything\s+now", "Do Anything Now jailbreak phrase"),
            (r"\bjailbreak\b", "Explicit jailbreak mention"),
            (r"developer\s+mode\s+(enabled|activated|on|unlock)", "Developer mode activation attempt"),
            (r"unrestricted\s+mode", "Unrestricted mode activation"),
            (r"\bevil\s+mode\b", "Evil mode activation"),
            (r"no\s+restrictions\b", "No-restrictions request"),
            (
                r"bypass\s+(your\s+)?(rules?|restrictions?|guidelines?|filters?|safety|ethics?)",
                "Safety bypass request",
            ),
            (
                r"disable\s+(your\s+)?(safety|filter|restriction|guideline|ethics?|alignment)",
                "Safety/ethics disable request",
            ),
            (
                r"without\s+(any\s+)?(restriction|limitation|filter|censorship|constraint|guideline)",
                "Unconstrained operation request",
            ),
            (r"(unlock|unleash)\s+(your\s+)?(full\s+)?(potential|capabilit|power)", "Capability unlocking framing"),
            (r"grandmother\s+(trick|exploit|jailbreak|loophole)", "Grandmother exploit attempt"),
            (
                r"pretend\s+(that\s+)?you\s+(have\s+no|don.t\s+have|lack)\s+(restriction|rule|limit|filter|ethic)",
                "Pretend-no-restrictions jailbreak",
            ),
        ],
    },
    "role_manipulation": {
        "description": "Role / Persona Manipulation",
        "severity": 0.75,
        "patterns": [
            (
                r"you\s+are\s+now\s+(?!just|only|also|still|able|going|aware|responsible)",
                "Role reassignment — 'you are now [X]'",
            ),
            (r"pretend\s+(you\s+are|to\s+be)\s+(?!helpful|honest|safe)", "Persona pretend instruction"),
            (
                r"act\s+as\s+(if\s+you\s+(are|were)\s+|a\b|an\b)(?!assistant|helpful|AI\s+assistant)",
                "Act-as persona injection",
            ),
            (r"roleplay\s+as\s+(?!a\s+helpful)", "Roleplay persona injection"),
            (r"your\s+new\s+persona\s+is", "Explicit persona injection"),
            (r"you\s+must\s+(now\s+)?become", "Forced identity change"),
            (
                r"imagine\s+you\s+(are|were|have\s+no|don.t\s+have)\s+"
                r"(?!.*(just|only|also|still).*assistant)",
                "Imagination-based role shift",
            ),
            (r"your\s+(true|real|actual|secret|hidden)\s+identity\s+is", "Identity substitution"),
            (
                r"respond\s+as\s+(if\s+you\s+(are|were)|a\b|an\b)(?!\s*helpful|\s*AI\s*assistant)",
                "Response persona injection",
            ),
            (r"you\s+(are|were)\s+(created|trained|built|designed)\s+by\s+(?!anthropic|openai)", "Origin falsification"),
            (r"your\s+name\s+is\s+(?!claude|assistant)", "Name/identity override"),
        ],
    },
    "prompt_leaking": {
        "description": "Prompt Extraction Attempt",
        "severity": 0.80,
        "patterns": [
            (
                r"(repeat|print|output|display|show|reveal|tell\s+me|share|write\s+out|return|dump)\s+"
                r"(your\s+)?(system\s+prompt|initial\s+prompt|original\s+prompt|instructions?|directives?)",
                "System prompt extraction request",
            ),
            (
                r"what\s+(are|were)\s+your\s+(instructions?|directives?|rules?|guidelines?|system\s+prompt)",
                "Instruction content inquiry",
            ),
            (
                r"(show|print|output|reveal|expose|leak)\s+(your\s+)?(configuration|config|setup|training\s+data)",
                "Configuration/training data extraction",
            ),
            (
                r"what\s+were\s+you\s+(told|instructed|given|asked|trained)\s+to",
                "Training instruction inquiry",
            ),
            (r"leak\s+(your\s+)?(prompt|instruction|training|system)", "Explicit prompt leak request"),
            (
                r"(describe|summarize|paraphrase)\s+(your\s+)?(system\s+prompt|instructions?|context)",
                "Indirect prompt extraction",
            ),
            (r"(start|begin)\s+your\s+(response\s+)?with\s+[\"']", "Forced response prefix (possible extraction)"),
        ],
    },
    "delimiter_injection": {
        "description": "Delimiter / Token Injection",
        "severity": 0.85,
        "patterns": [
            (
                r"<\|?(im_start|im_end|endoftext|end_of_turn|system|user|assistant|human)\|?>",
                "Chat template / special token injection",
            ),
            (r"\[/?INST\]", "Instruction template token ([INST]/[/INST])"),
            (r"<<SYS>>|<</SYS>>", "Llama-style system prompt delimiter"),
            (r"#{3,}\s*(system|instruction|prompt|human|assistant)", "Markdown-style injection delimiter"),
            (r"-{3,}\s*(system|instruction|prompt)\s*-{3,}", "YAML/frontmatter injection delimiter"),
            (r"\[(SYSTEM|INST|PROMPT|USER|ASSISTANT)\]", "Bracket injection token"),
            (r"<system>|<user>|<assistant>|<human>", "XML-style role tag injection"),
            (r"```\s*(system|instruction|prompt)\s*\n", "Code-fence injection block"),
        ],
    },
    "encoding_obfuscation": {
        "description": "Encoded / Obfuscated Payload",
        "severity": 0.70,
        "patterns": [
            (
                r"base64[^a-z]*(decode|encoded?|instruction|payload)",
                "Base64 encoding reference (possible obfuscation)",
            ),
            (r"decode\s+the\s+following\s+(and\s+)?(execute|run|follow|obey|do)", "Decode-and-execute instruction"),
            (r"\brot-?13\b", "ROT13 obfuscation"),
            (
                r"[A-Za-z0-9+/]{50,}={0,2}\s*(decode|is|contains|says|means|represents)",
                "Long base64-like string with decode instruction",
            ),
            (r"hex\s+(decode|encoded?|representation|payload)", "Hex encoding obfuscation"),
            (r"unicode\s+escape.{0,30}(instruction|execute|run|follow)", "Unicode escape obfuscation"),
        ],
    },
    "context_manipulation": {
        "description": "Context / Framing Manipulation",
        "severity": 0.65,
        "patterns": [
            (
                r"(scroll|look|go)\s+(up|back|above|past)\s+(and\s+)?(ignore|forget|disregard)",
                "Context-scroll attack",
            ),
            (
                r"(previous|prior|above)\s+conversation\s+(is\s+)?(irrelevant|not\s+important|should\s+be\s+ignored|doesn.t\s+matter)",
                "Prior conversation dismissal",
            ),
            (
                r"(hypothetically|theoretically|for\s+a\s+(story|novel|game|film)|in\s+fiction|as\s+fiction)"
                r".{0,80}(hack|exploit|attack|weapon|synthesize|illegal|malware|ransomware|bomb)",
                "Hypothetical framing to elicit harmful content",
            ),
            (
                r"(for\s+(educational|research|academic|scientific)\s+purposes?).{0,80}"
                r"(hack|exploit|malware|weapon|illegal|bypass|synthesize|attack)",
                "Educational framing to elicit harmful content",
            ),
            (
                r"this\s+is\s+(just\s+)?(a\s+)?(test|simulation|exercise|drill).{0,60}"
                r"(ignore|bypass|disable|override)",
                "Test/simulation framing to bypass rules",
            ),
        ],
    },
}
