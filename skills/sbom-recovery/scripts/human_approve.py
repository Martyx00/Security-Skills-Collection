"""Terminal-only approval of the review file: ``python3 -I -B <skill folder>/scripts/human_approve.py``.

Run by a person in a terminal from the workspace folder. It is the strong form of approval: it shows what approving means,
asks for the word APPROVE and then runs the same code path as ``sbom.py approve`` (strict read-back, approved copy, approval
snapshot) with the evidence ``tty``. Nothing in a plain skill install stops an agent from running it too (a pseudo-terminal
is easy to allocate), so ``tty`` records that a terminal was present, not who sat at it (references/limitations.md).

Exit codes: 0 approved or already approved, 1 refused (read-back, not at the gate, not confirmed, file changed),
2 not a terminal or a usage/layout problem. Importing this file runs nothing.
"""
import sys

sys.dont_write_bytecode = True

import os                                      # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.realpath(os.path.abspath(__file__))))

DISCLOSURE = ("Approval authorizes sending the names and versions of rows with include=yes and action=lookup to the NVD API.")
CONFIRM_PROMPT = "Type APPROVE and press Enter to approve this file: "
DIFF_LINES = 50


def _out(text=""):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _err(text):
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _show_summary(run, sha256, read_back):
    review = run.data.get("review") or {}
    _out("Review file: %s" % (review.get("path") or "the review file"))
    _out("Rows: %s (include=yes: %s)" % (review.get("rows", "?"), review.get("rows_included", "?")))
    _out("SHA-256: %s" % sha256)
    diff = read_back["diff"]
    if not diff:
        _out("Edits since the file was written: none.")
    else:
        _out("Edits since the file was written (%d cell%s):" % (len(diff), "" if len(diff) == 1 else "s"))
        for item in diff[:DIFF_LINES]:
            _out("  %s %s: %r -> %r" % (item["id"], item["column"], item["old"], item["new"]))
        if len(diff) > DIFF_LINES:
            _out("  ... and %d more" % (len(diff) - DIFF_LINES))
    if read_back["readonly_changes"]:
        _out("Changes to read-only columns (ignored): %d" % len(read_back["readonly_changes"]))
    _out("")
    _out(DISCLOSURE)


def main(argv=None, script_file=None, overrides=None):
    """Run the interactive approval; returns the exit code. ``overrides`` is for tests (in-process use only)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        _err("usage: human_approve.py (no arguments)")
        return 2
    from pathlib import Path
    from sbomlib import approval, errors, fsio, paths, state
    from sbomlib.context import make_context
    script = Path(script_file or os.path.abspath(__file__))
    try:
        layout = paths.resolve_layout(script, Path(os.getcwd()))
    except (errors.LayoutError, OSError) as exc:
        _err(str(exc))
        return 2
    ctx = make_context(layout, overrides=overrides)
    if not ctx.tty:
        _err("human_approve.py must be run by a person in a terminal (standard input and output must be a terminal).")
        return 2
    try:
        return _approve(ctx, approval, errors, fsio, state)
    except errors.SbomError as exc:
        _err("Not approved: %s" % exc.message)
        return 1


def _approve(ctx, approval, errors, fsio, state):
    run = state.load_run(ctx)
    if run is None:
        _out("There is no run. Ask the agent to start one first.")
        return 1
    ctx.run_id = run.run_id
    ctx.log.run_id = run.run_id
    if run.completed:
        _out(approval.RUN_COMPLETED_MESSAGE)
        return 1
    if run.gate == "none" or not (run.data.get("review") or {}).get("path"):
        _out(approval.NOT_AT_GATE_MESSAGE)
        return 1
    try:
        with open(str(approval.review_path(ctx)), "rb") as handle:
            data = handle.read()
    except OSError:
        _out("The review file %s cannot be read." % ctx.layout.shown("review/cpe-lookup-names.csv"))
        return 1
    sha256 = fsio.sha256_bytes(data)
    approvals = run.data.get("approvals") or []
    if run.gate == "approved" and approvals and not approvals[-1].get("stale") and approvals[-1].get("sha256") == sha256:
        _out("This review file is already approved (approval %s)." % approvals[-1].get("n"))
        _out('Now type "continue" in the chat so the agent runs next.')
        return 0
    from sbomlib import cpe
    try:
        read_back = cpe.read_back(ctx, data, cpe.load_written_rows(ctx))
    except errors.ReviewRefused as exc:
        _out(exc.message)
        return 1
    _show_summary(run, sha256, read_back)
    try:
        answer = input(CONFIRM_PROMPT)
    except (EOFError, KeyboardInterrupt):
        answer = ""
        _out("")
    if answer.strip() != "APPROVE":
        _out("Not approved.")
        return 1
    try:
        with state.op_mutex(ctx, "human_approve"):
            run = state.load_run(ctx)
            if run is None:
                _out("There is no run.")
                return 1
            result = approval.approve(ctx, run, mode="tty", expected_sha256=sha256)
    except errors.Busy as exc:
        _out("Not approved: %s" % exc.message)
        return 1
    block = result.get("approval") or {}
    if result.get("ok") and block.get("status") in ("approved", "already_approved"):
        _out(result.get("message", "Approved."))
        _out('Now type "continue" in the chat so the agent runs next.')
        return 0
    _out("Not approved: %s" % result.get("message", "refused"))
    return 1


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        _err("Python 3.9 or newer is required")
        sys.exit(2)
    sys.exit(main())
