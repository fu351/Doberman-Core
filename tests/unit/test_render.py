"""Presentation-layer tests for ``doberman.render`` -- color + wrapping only.

No engine/decision logic under test here: these tests cover the color gate
(``NO_COLOR`` / Click's own TTY detection), the fixed-width verdict label,
and terminal-width-aware wrapping -- the piece that replaces the old
unwrapped (sometimes 242-char) CLI lines.
"""

import re

import click

import doberman.render as render
from doberman.models import Verdict

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _FakeStream:
    """A minimal stdout stand-in so TTY detection is deterministic in tests."""

    def __init__(self, is_tty: bool) -> None:
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


def test_no_color_env_disables_color_when_non_empty(monkeypatch):
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    monkeypatch.setenv("NO_COLOR", "1")
    assert render.supports_color() is False

    monkeypatch.setenv("NO_COLOR", "0")  # any non-empty value is a signal, whatever it says
    assert render.supports_color() is False

    # https://no-color.org: present *and non-empty*. An exported-but-empty var is not a signal.
    monkeypatch.setenv("NO_COLOR", "")
    assert render.supports_color() is True


def test_supports_color_defers_to_tty_detection_when_no_color_unset(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    assert render.supports_color() is True

    monkeypatch.setattr(render.sys, "stdout", _FakeStream(False))
    assert render.supports_color() is False


def test_no_color_produces_zero_ansi_escapes(monkeypatch):
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    monkeypatch.setenv("NO_COLOR", "1")
    for verdict in Verdict:
        label = render.verdict_label(verdict)
        assert _ANSI_RE.search(label) is None


def test_colored_and_uncolored_labels_share_visible_width(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    for verdict in Verdict:
        monkeypatch.setattr(render, "supports_color", lambda: True)
        colored = render.verdict_label(verdict)
        monkeypatch.setattr(render, "supports_color", lambda: False)
        plain = render.verdict_label(verdict)

        assert click.unstyle(colored) == plain
        assert len(click.unstyle(colored)) == len(plain) == render._LABEL_WIDTH


def test_wrap_detail_never_exceeds_an_explicit_clamped_width():
    text = "word " * 60  # well over any clamp bound
    below_min = render.wrap_detail(text, indent=4, width=10)
    assert all(len(line) <= 60 for line in below_min)

    above_max = render.wrap_detail(text, indent=4, width=500)
    assert all(len(line) <= 78 for line in above_max)


def test_wrap_detail_clamps_the_real_terminal_size_too(monkeypatch):
    monkeypatch.setattr(render.shutil, "get_terminal_size", lambda fallback=(100, 24): (20, 24))
    lines = render.wrap_detail("some explanation text that needs wrapping", indent=4)
    assert all(len(line) <= 60 for line in lines)

    monkeypatch.setattr(render.shutil, "get_terminal_size", lambda fallback=(100, 24): (300, 24))
    lines = render.wrap_detail("word " * 40, indent=4)
    assert all(len(line) <= 78 for line in lines)


def test_verdict_rich_style_is_bold_bright_red_for_block():
    # BLOCK must be the most legible element (design critique P1): bold +
    # bright_red, not the dim `bold red` a second copy of this palette once had.
    assert render.verdict_rich_style(Verdict.BLOCK) == "bold bright_red"


def test_verdict_rich_style_matches_the_cli_palette_for_every_verdict():
    # One source of truth: the Rich style string and the Typer/Click kwargs in
    # `_VERDICT_STYLES` must describe the same color for every verdict, so a
    # Rich-based renderer (the `tui` decision browser) can never drift from
    # `doberman log`.
    for verdict in Verdict:
        style = render.verdict_rich_style(verdict)
        kwargs = render._VERDICT_STYLES[verdict]
        assert str(kwargs["fg"]) in style
        assert kwargs.get("bold", False) is ("bold" in style)


def test_verdict_rich_style_on_an_unrecognized_value_is_empty_not_a_raise():
    assert render.verdict_rich_style("not-a-verdict") == ""  # type: ignore[arg-type]


def test_verdict_rich_style_chip_is_black_on_a_solid_background_for_block_and_auth():
    # Inverse "chip" style (design critique item 14): pure black (#000000, not
    # the named "black", which this theme renders too dark to clear 4.5:1 on
    # bright_red) text on a solid background - never the plain foreground-only
    # style default (chip=False) uses.
    assert render.verdict_rich_style(Verdict.BLOCK, chip=True) == "bold #000000 on bright_red"
    assert render.verdict_rich_style(Verdict.AUTH, chip=True) == "bold #000000 on yellow"


def test_verdict_rich_style_chip_leaves_pass_as_plain_colored_text():
    # PASS isn't a warning - it keeps its ordinary style, chip or not.
    assert render.verdict_rich_style(Verdict.PASS, chip=True) == render.verdict_rich_style(
        Verdict.PASS
    )


def test_risk_rich_style_known_levels():
    assert render.risk_rich_style("critical") == "bold #000000 on bright_red"
    assert render.risk_rich_style("high") == "bold #000000 on dark_orange"
    assert render.risk_rich_style("medium") == "bold #000000 on yellow"
    assert render.risk_rich_style("low") == ""


def _wcag_contrast_ratio(rgb1, rgb2) -> float:
    def linear(channel: int) -> float:
        c = channel / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(rgb) -> float:
        r, g, b = rgb
        return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)

    l1, l2 = luminance(rgb1), luminance(rgb2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_risk_chips_meet_the_contrast_floor_and_form_a_gradient():
    # round 4 design critique items 5 + 10: critical/high must not share a
    # color (a real gradient), and every level above low must clear 4.5:1
    # (medium alone, as plain foreground text, measured only 4.06:1 under the
    # cursor row). Resolve each style's actual truecolor via Rich itself,
    # rather than trusting the style string's color name.
    from rich.style import Style

    fills = {}
    for risk in ("critical", "high", "medium"):
        style = Style.parse(render.risk_rich_style(risk))
        text_rgb = style.color.get_truecolor()
        bg_rgb = style.bgcolor.get_truecolor()
        fills[risk] = (text_rgb, bg_rgb)
        ratio = _wcag_contrast_ratio(
            (text_rgb.red, text_rgb.green, text_rgb.blue),
            (bg_rgb.red, bg_rgb.green, bg_rgb.blue),
        )
        assert ratio >= 4.5, (risk, text_rgb, bg_rgb, ratio)

    assert fills["critical"][1] != fills["high"][1]  # distinct fills, a real gradient


def test_risk_rich_style_unrecognized_value_is_empty_not_a_raise():
    assert render.risk_rich_style("not-a-risk") == ""


def test_humanize_auth_result_known_values():
    assert render.humanize_auth_result("executed") == "ran"
    assert render.humanize_auth_result("blocked") == "blocked"
    assert render.humanize_auth_result("denied") == "denied"
    assert (
        render.humanize_auth_result("soft_confirm+memory")
        == "approved via 5-minute memory (soft_confirm)"
    )


def test_humanize_auth_result_short_form_for_narrow_columns():
    # The `tui` browser's 7-wide auth column can't fit the full label - only
    # entries with a distinct short form change; everything else (already
    # short) is identical whether or not `short=True`.
    assert render.humanize_auth_result("soft_confirm+memory", short=True) == "mem ok"
    assert render.humanize_auth_result("executed", short=True) == "ran"
    assert render.humanize_auth_result("blocked", short=True) == "blocked"


def test_humanize_auth_result_none_or_empty_is_a_dash():
    assert render.humanize_auth_result(None) == "-"
    assert render.humanize_auth_result("") == "-"


def test_humanize_auth_result_unrecognized_value_falls_back_to_humanized_raw():
    # A raw auth-tier/method name not in the small explicit map (e.g. "totp",
    # a future value) must never raise - it's shown with underscores as spaces.
    assert render.humanize_auth_result("async_timeout") == "async timeout"
    assert render.humanize_auth_result("totp") == "totp"


def test_humanize_auth_result_pending_for_an_unanswered_auth_row():
    # round 5 design critique item 7: a still-open AUTH row is a real,
    # ongoing state - it must never look identical to a PASS/BLOCK row's
    # genuine "no auth step at all" dash.
    assert render.humanize_auth_result(None, verdict="AUTH") == "pending - not yet answered"
    assert render.humanize_auth_result(None, verdict="AUTH", short=True) == "pending"
    assert render.humanize_auth_result(None, verdict="PASS") == "-"
    assert render.humanize_auth_result(None, verdict="BLOCK") == "-"
    assert render.humanize_auth_result(None) == "-"  # no verdict given - old behavior


def test_wrap_detail_keeps_a_quoted_doberman_command_on_one_line():
    # Coordinator CI fix: 'doberman dash' broke across two wrapped lines on a
    # narrower-than-local CI terminal - a quoted 'doberman <command>' phrase
    # must now stay unbreakable regardless of width.
    text = render.next_step_line("AUTH", tui_hint=False)
    lines = render.wrap_detail(text, indent=0, width=60)
    assert "'doberman dash'" in " ".join(lines)
    assert not any(line.rstrip().endswith("'doberman") for line in lines)


def test_wrap_detail_keeps_a_multi_word_quoted_doberman_command_on_one_line():
    text = render.next_step_line("BLOCK", tui_hint=False)
    lines = render.wrap_detail(text, indent=0, width=60)
    assert "'doberman review --yes'" in " ".join(lines)
    assert "'doberman mode'" in " ".join(lines)


def test_format_utc_timestamp_strips_microseconds_and_labels_utc():
    # round 8 design critique item 7: `doberman log`'s timestamp column must
    # read the same format the tui why panel shows - no microseconds, an
    # explicit " UTC" suffix, a space (not "T") between date and time.
    assert (
        render.format_utc_timestamp("2026-07-30T00:00:01.123456+00:00") == "2026-07-30 00:00:01 UTC"
    )
    assert render.format_utc_timestamp("2026-07-30T00:00:01Z") == "2026-07-30 00:00:01 UTC"


def test_format_utc_timestamp_assumes_naive_values_are_already_utc():
    assert render.format_utc_timestamp("2026-07-30T00:00:01") == "2026-07-30 00:00:01 UTC"


def test_format_utc_timestamp_converts_a_non_utc_offset():
    assert render.format_utc_timestamp("2026-07-30T05:00:01+05:00") == "2026-07-30 00:00:01 UTC"


def test_format_utc_timestamp_never_raises_on_junk_or_missing_values():
    assert render.format_utc_timestamp(None) == "None"
    assert render.format_utc_timestamp("not-a-timestamp") == "not-a-timestamp"
    assert render.format_utc_timestamp(12345) == "12345"


def test_a_242_char_line_wraps_into_multiple_lines():
    phrase = "Shell, package, or git egress requires authentication because "
    text = (phrase * 4)[:242]
    assert len(text) == 242

    lines = render.wrap_detail(text, indent=4, width=100)
    assert len(lines) > 1
    assert all(len(line) <= 78 for line in lines)


def test_wrap_detail_hang_indents_continuation_past_a_marker():
    """A `"- name: "`-style caller can ask for continuation lines to land
    under the text, not under the marker."""
    text = "- Config: " + ("detail word " * 20)
    lines = render.wrap_detail(text, indent=2, width=40, hang=2)
    assert len(lines) > 1
    assert lines[0].startswith("  - Config:")
    for line in lines[1:]:
        assert line.startswith("    ")  # indent(2) + hang(2)
        assert not line.startswith("     ")  # exactly 4, not more


def test_wrap_detail_never_breaks_inside_a_path_token():
    windows_path = "C:\\Users\\someone\\AppData\\Local\\Doberman\\policies-with-a-long-name.yaml"
    text = f"present but failed to load: {windows_path} (corrupt?)"
    lines = render.wrap_detail(text, indent=0, width=40)
    # The path is far longer than width=40; it must still land whole on one
    # line rather than being force-split mid-directory-name.
    assert any(windows_path in line for line in lines)


def test_wrap_detail_force_breaks_an_overlong_non_path_token():
    # #622: a token far wider than the clamp that is NOT a path must be
    # hard-wrapped so no rendered line overflows the width.
    token = "deadbeefcafefeed" * 8  # 128 chars, no break opportunities
    lines = render.wrap_detail(token, indent=4, width=60)
    assert len(lines) > 1
    assert all(len(line) <= 60 for line in lines)
    # No character of the token is dropped when it is force-broken.
    assert "".join(line.strip() for line in lines) == token


def test_wrap_detail_force_breaks_an_overlong_option_that_merely_contains_a_slash():
    # #622: `--foo/bar/...` contains a slash but is an option flag, not a path,
    # so it must be force-broken rather than allowed to run past the width.
    option = "--foo/bar/baz-" + "some-extremely-long-value" * 4
    lines = render.wrap_detail(option, indent=0, width=60)
    assert len(lines) > 1
    assert all(len(line) <= 60 for line in lines)


def test_wrap_detail_never_breaks_a_posix_path_or_url_token():
    # The narrowing in #622 must not regress genuine paths/URLs: a POSIX path
    # and a scheme URL, both far wider than the width, still land whole.
    posix_path = "/var/lib/doberman/policies/a-very-long-policy-file-name.yaml"
    url = "https://example.com/some/very/long/path/that/exceeds/the/wrap/width"
    for token in (posix_path, url):
        lines = render.wrap_detail(f"see {token} for detail", indent=0, width=40)
        assert any(token in line for line in lines)


def test_next_step_line_known_verdicts_and_pass_has_none():
    # Shared by the `tui` browser's docked "Next" widget and `doberman log
    # --why` (round 4 design critique item 8) - one source of truth.
    block = render.next_step_line("BLOCK")
    assert block is not None
    assert block.startswith("Next:")
    assert "doberman mode" in block

    auth = render.next_step_line("AUTH")
    assert auth is not None
    assert auth.startswith("Next:")
    assert "doberman dash" in auth

    assert render.next_step_line("PASS") is None
    assert render.next_step_line(None) is None
    assert render.next_step_line("ALLOW") is None  # unrecognized - never raises
