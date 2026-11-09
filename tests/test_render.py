from ircopilot.render import Style, render_answer

PLAIN = Style(False)


def test_structure_is_spaced_and_wrapped() -> None:
    text = (
        "**Cause:** The container ran out of memory and was killed by the kernel OOM killer, which is why it exited "
        "with code 137 [S1].\nSteps:\n1. Check the memory limit set for the container [S2].\n2. Raise the limit [S1, S2].\n"
        "```bash\nkubectl describe pod web\n```"
    )
    out = render_answer(text, PLAIN, w=60)
    lines = out.split("\n")
    assert lines[0] == "Cause"
    assert all(len(ln) <= 60 for ln in lines)
    assert "**" not in out and "```" not in out
    assert "\n\n  2. Raise the limit [S1, S2]." in out  # blank line between steps
    assert "    kubectl describe pod web" in out


def test_wrapped_citation_keeps_indent() -> None:
    out = render_answer("1. " + "word " * 11 + "end [S5].", PLAIN, w=60)
    assert all(ln.startswith("  ") for ln in out.split("\n"))


def test_no_escape_codes_without_color() -> None:
    assert "\x1b" not in render_answer("Cause: x [S1]\n1. y [S2]", PLAIN)


def test_color_only_adds_our_codes() -> None:
    out = render_answer("Cause: disk full [S1]", Style(True))
    assert "\x1b[1mCause\x1b[0m" in out and "\x1b[2m[S1]\x1b[0m" in out
