"""Markdown-inline sanitization for the step-summary renderer.

The watchdog summary (stdout + ``$GITHUB_STEP_SUMMARY``) is GitHub-Flavored Markdown.
The only field interpolated into it that is not a controlled enum/number is the
operator-chosen ``service_name`` — an unrestricted non-blank string. Rendered raw, a
hostile or mistyped name could forge headings, verdicts, links, images, raw HTML, or
extra table/list rows via newlines and Markdown/HTML metacharacters — and GitHub would
additionally auto-link any bare ``www.`` domain, http(s):// URL, or email address it
contains, even with no link syntax at all.

:func:`sanitize_markdown_inline` neutralizes that: it collapses every newline, tab, and
control-whitespace run to a single space (so a value can never span lines or begin a
new block-level construct), then backslash-escapes the inline Markdown metacharacters
and the URL/email joiners ``. : / @`` (so no autolink candidate stays contiguous) and
HTML-entity-encodes ``&``/``<``/``>`` (so no code span, emphasis, link, image, or raw
HTML tag can form). The human-readable text stays visible; only its power to create
*structure or links* is removed.

This is deliberately **separate** from the email path in :mod:`watchdog.notify`, which
renders HTML and uses ``html.escape``. Markdown and HTML need different escaping, so the
two paths are not shared.
"""

from __future__ import annotations

import re

# Runs of ASCII/Unicode whitespace, C0 controls, DEL, and C1 controls collapse to a
# single space. ``\s`` (Unicode) also folds exotic separators like U+2028/U+2029/U+0085.
_COLLAPSE_WHITESPACE = re.compile(r"[\s\x00-\x1f\x7f-\x9f]+")

# Single-pass translation table. ``str.translate`` maps original code points only, so
# the replacement text (e.g. the ``amp;`` in ``&amp;``) is never re-processed — no
# double-encoding and no ordering hazard between ``\`` and the other escapes.
_MD_METACHARS: dict[str, str] = {
    "\\": "\\\\",
    "`": "\\`",
    "*": "\\*",
    "_": "\\_",
    "[": "\\[",
    "]": "\\]",
    "(": "\\(",
    ")": "\\)",
    "!": "\\!",
    "#": "\\#",
    "|": "\\|",
    "~": "\\~",
    # URL/email joiners: escaped so GitHub's automatic linking of bare "www." domains,
    # http(s):// URLs, and email addresses cannot fire. GFM renders "\." "\:" "\/" "\@"
    # as the same literal characters, but the backslash breaks the contiguous run the
    # autolink extension scans for, so no autolink candidate survives.
    ".": "\\.",
    ":": "\\:",
    "/": "\\/",
    "@": "\\@",
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
}
_TRANSLATION = str.maketrans(_MD_METACHARS)


def sanitize_markdown_inline(text: str) -> str:
    """Render *text* safe to interpolate inline into Markdown.

    Collapses control/whitespace to single spaces (trimmed), then escapes inline
    Markdown metacharacters, the URL/email joiners ``. : / @`` (to defeat GFM autolinking
    of bare domains/URLs/emails), and entity-encodes HTML-significant characters.
    Block-only markers that are not also joiners (``-``, ``+``, ``=``) are intentionally
    left untouched: once newlines are gone they can never sit at the start of a line, so
    simple and hyphenated names such as ``AlphaService`` or ``orders-api-1`` stay
    byte-for-byte clean in both raw stdout and the rendered summary.
    """
    collapsed = _COLLAPSE_WHITESPACE.sub(" ", text).strip()
    return collapsed.translate(_TRANSLATION)
