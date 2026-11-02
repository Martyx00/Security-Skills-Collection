"""Entry point of the sbom-recovery skill: the bootstrap only. All logic lives in the sbomlib package next to this file.

Run as: <python> -I -B <skill folder>/scripts/sbom.py <subcommand>   (working directory: the workspace folder, the folder
whose subfolders are the repositories; the skill folder is wherever the skill is installed and is never written to)
Importing this file runs nothing.
"""
import sys

sys.dont_write_bytecode = True

import os                                      # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.realpath(os.path.abspath(__file__))))


def _refuse_old_python():
    sys.stdout.write('{"ok": false, "cmd": null, "next_action": "error", "error": {"code": "UNSAFE_LAYOUT", '
                     '"message": "Python 3.9 or newer is required", "retryable": false}, '
                     '"message": "Python 3.9 or newer is required"}\n')
    sys.stdout.flush()
    sys.exit(3)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        _refuse_old_python()
    from pathlib import Path
    from sbomlib import cli_core
    sys.exit(cli_core.main(sys.argv[1:], script_file=Path(__file__)))
