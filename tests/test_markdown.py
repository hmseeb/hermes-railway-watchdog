"""RED first: Markdown-inline sanitizer for summary rendering.

The public ``service_name`` is an operator-chosen, unrestricted non-blank string that
is interpolated directly into a GitHub-Flavored-Markdown step summary. A hostile or
fat-fingered name containing newlines, heading markers, link/image syntax, raw HTML,
pipes, backticks, or control whitespace must not be able to forge headings, verdicts,
links, images, HTML, or extra rows. These tests use entirely fabricated malicious
names. This sanitizer is distinct from the email path's HTML escaping.
"""

from __future__ import annotations

from watchdog.markdown import sanitize_markdown_inline

# --- whitespace / control normalization ---------------------------------------


def test_newlines_tabs_and_controls_collapse_to_single_spaces():
    out = sanitize_markdown_inline("orders\r\napi\tservice\x00x")
    assert "\n" not in out and "\r" not in out and "\t" not in out
    assert "\x00" not in out
    assert out == "orders api service x"


def test_all_c0_controls_and_del_are_stripped():
    raw = "a" + "".join(chr(c) for c in range(0x20)) + "\x7f" + "b"
    out = sanitize_markdown_inline(raw)
    assert out == "a b"
    assert all(ord(ch) >= 0x20 and ord(ch) != 0x7f for ch in out)


def test_exotic_line_separators_do_not_survive():
    # U+2028/U+2029 (line/paragraph separators) and U+0085 (NEL) are treated as line
    # breaks by some renderers; all must fold to ordinary spaces.
    out = sanitize_markdown_inline("a\u2028b\u2029c\x85d")
    assert out == "a b c d"


def test_leading_and_trailing_whitespace_is_trimmed():
    assert sanitize_markdown_inline("  spaced  ") == "spaced"


# --- fake structure / row / heading injection ---------------------------------


def test_fake_row_injection_is_flattened_to_one_line():
    evil = "evil\n- ghost: healthy | action=none | elapsed=0.00s | PASS"
    out = sanitize_markdown_inline(evil)
    assert "\n" not in out
    assert "ghost" in out          # text preserved, but inline only
    assert "\\|" in out            # the forged pipes are escaped


def test_heading_marker_is_escaped():
    assert sanitize_markdown_inline("# pwned") == "\\# pwned"


# --- links / images -----------------------------------------------------------


def test_markdown_link_is_neutralized_but_text_remains():
    out = sanitize_markdown_inline("[click](http://evil.test)")
    assert "](" not in out                    # no functional link joint
    assert "\\[" in out and "\\]" in out
    assert "\\(" in out and "\\)" in out
    assert "click" in out and "evil" in out and "test" in out  # readable letters stay


def test_markdown_image_is_neutralized():
    out = sanitize_markdown_inline("![alt](http://evil.test/x.png)")
    assert "![" not in out
    assert out.startswith("\\!\\[")


# --- raw HTML -----------------------------------------------------------------


def test_html_tag_is_entity_encoded():
    out = sanitize_markdown_inline("<img src=x onerror=alert(1)>")
    assert "<" not in out and ">" not in out
    assert "&lt;img" in out and "&gt;" in out
    assert "\\(" in out and "\\)" in out  # the alert(1) parens are also escaped


def test_ampersand_is_entity_encoded():
    assert sanitize_markdown_inline("Tom & Jerry") == "Tom &amp; Jerry"


def test_ampersand_encoding_is_not_double_encoded():
    # Single pass: the inserted "amp;" must not be re-processed.
    assert sanitize_markdown_inline("&amp;") == "&amp;amp;"


# --- inline emphasis / code / pipes / backslash -------------------------------


def test_pipes_are_escaped():
    assert sanitize_markdown_inline("a | b | c") == "a \\| b \\| c"


def test_backticks_are_escaped():
    assert sanitize_markdown_inline("`rm -rf`") == "\\`rm -rf\\`"


def test_emphasis_markers_are_escaped():
    out = sanitize_markdown_inline("*bold* _ital_ ~strike~")
    assert out == "\\*bold\\* \\_ital\\_ \\~strike\\~"


def test_backslash_is_escaped_first():
    assert sanitize_markdown_inline("a\\b") == "a\\\\b"


# --- GFM autolink defense -----------------------------------------------------


def test_www_prefixed_name_is_not_autolinkable():
    # GitHub auto-links a bare "www." domain even without link syntax.
    out = sanitize_markdown_inline("www.example.test")
    assert out == "www\\.example\\.test"
    assert "www." not in out          # the "www." autolink trigger is broken
    assert "www" in out and "example" in out and "test" in out


def test_bare_url_is_not_autolinkable():
    out = sanitize_markdown_inline("https://example.test/path")
    assert out == "https\\:\\/\\/example\\.test\\/path"
    assert "://" not in out                 # scheme joiner broken
    assert "https:" not in out
    assert "example.test" not in out        # no contiguous domain survives
    assert "example" in out and "path" in out


def test_bare_email_is_not_autolinkable():
    out = sanitize_markdown_inline("ops@example.test")
    assert out == "ops\\@example\\.test"
    assert "ops@example" not in out            # no contiguous email candidate
    assert out.count("@") == out.count("\\@")  # every @ is escaped
    assert "example.test" not in out           # domain half also broken
    assert "ops" in out and "example" in out


# --- benign names stay clean --------------------------------------------------


def test_benign_service_names_are_unchanged():
    # Simple and hyphenated names contain none of the escaped joiners, so they stay
    # byte-for-byte identical in both plain-text stdout and the rendered summary.
    for name in ("AlphaService", "BetaService", "orders-api-1", "orders-api-a", "internal-name-a"):
        assert sanitize_markdown_inline(name) == name
