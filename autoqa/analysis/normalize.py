"""Shared text normalization for identity comparisons.

Both clustering ("are these the same bug?") and minimization ("is this still
the same failure?") need to compare error text while ignoring the specific
values that happened to trigger it. Keeping one implementation means those two
questions can never drift apart and disagree.
"""

from __future__ import annotations

import re

# Volatile substrings that would otherwise split one bug into many clusters.
# Order matters: specific patterns must run before the generic number one.
#
# Quoted values are the big one. An error like
#   No such file or directory: 'a.txt'
# is the SAME defect as
#   No such file or directory: '../../etc/passwd'
# and must not be reported as two issues just because the fuzzer sent two
# different values into it.
_NOISE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<uuid>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"), "<ts>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<addr>"),
    # Escaped-double-quoted first: a JSON body embeds the offending value as
    # \"...\", and that value may itself contain bare single quotes (a SQL
    # injection payload, say). Consuming it as one unit here stops the
    # single-quote rule below from pairing quotes across value boundaries.
    (re.compile(r'\\"(?:[^"\\]|\\.)*\\"'), "<val>"),
    (re.compile(r'"(?:[^"\\]|\\.)*"'), "<val>"),
    (re.compile(r"'[^']*'"), "<val>"),
    (re.compile(r"line \d+"), "line <n>"),
    (re.compile(r"\b\d+\b"), "<n>"),
)


def normalize(text: str) -> str:
    """Strip run-specific detail so two reports of one bug compare equal."""
    for pattern, replacement in _NOISE:
        text = pattern.sub(replacement, text)
    return text.strip().lower()
