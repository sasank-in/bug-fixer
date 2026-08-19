"""Realign a model reply whose base indentation does not match the window.

Models routinely return the snippet indented as if it were nested, or flush-left
when it was nested. That fails an in-place syntax check and throws away an
otherwise correct fix over whitespace alone.

The relative structure inside the reply is what carries the meaning; the base
level is mechanical, so it is worth correcting rather than rejecting. This is
deliberately conservative — it shifts every line by one constant amount and never
reflows anything, so a reply whose *internal* indentation is wrong still fails
validation, which is the outcome we want.
"""

from __future__ import annotations


def base_indent(text: str) -> int | None:
    """Smallest indentation across non-blank lines, or None if there are none."""
    widths = [
        len(line) - len(line.lstrip()) for line in text.splitlines() if line.strip()
    ]
    return min(widths) if widths else None


def realign(replacement: str, original: str) -> str:
    """Shift `replacement` so its base indentation matches `original`."""
    want = base_indent(original)
    got = base_indent(replacement)
    if want is None or got is None or want == got:
        return replacement

    trailing = "\n" if replacement.endswith("\n") else ""
    lines = replacement.splitlines()

    if got > want:
        shift = got - want
        adjusted = [
            line[shift:] if len(line) - len(line.lstrip()) >= shift else line.lstrip()
            for line in lines
        ]
    else:
        pad = " " * (want - got)
        # Blank lines stay blank; padding them would add trailing whitespace.
        adjusted = [pad + line if line.strip() else line for line in lines]

    return "\n".join(adjusted) + trailing
