from setuptools import setup, find_packages

setup(
    name="prompt-injection-detector",
    version="1.0.0",
    description="Detect prompt injection attack patterns in text inputs",
    author="RainFox418",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=["colorama>=0.4.6"],
    entry_points={
        "console_scripts": [
            "pid=cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Text Processing",
    ],
)
