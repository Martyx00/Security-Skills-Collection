"""Exception hierarchy of the pack (contract section 3.2)."""
from __future__ import annotations

from typing import Any, Dict


class SbomError(Exception):
    """Base class. ``code`` is the stable machine-readable error code."""

    code = "INTERNAL"
    retryable = False

    def __init__(self, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """The ``error`` object of the result envelope (contract section 5.2)."""
        return {"code": self.code, "message": self.message, "retryable": bool(self.retryable)}


class LayoutError(SbomError):
    code = "UNSAFE_LAYOUT"


class PathEscape(SbomError):
    code = "PATH_ESCAPE"


class StateError(SbomError):
    code = "STATE_CORRUPT"


class Busy(SbomError):
    code = "BUSY"
    retryable = True


class DriverBusy(SbomError):
    code = "DRIVER_BUSY"
    retryable = True


class BudgetExceeded(SbomError):
    code = "BUDGET_EXCEEDED"
    retryable = True


class GitForbidden(SbomError):
    code = "GIT_FORBIDDEN"


class GitError(SbomError):
    """detail: args, returncode, stderr (truncated to 500 characters)."""

    code = "GIT_ERROR"


class GitUnreadable(GitError):
    """"dubious ownership" and similar: the repository is reported unreadable."""

    code = "GIT_UNREADABLE"


class GitMissing(SbomError):
    """git is not installed (selfcheck / start fail fast with GIT_MISSING)."""

    code = "GIT_MISSING"


class GitTooOld(SbomError):
    """git is older than 2.25 (selfcheck / start fail fast with GIT_TOO_OLD)."""

    code = "GIT_TOO_OLD"


class NetworkUnavailable(SbomError):
    code = "NETWORK_UNAVAILABLE"


class CsvReadError(SbomError):
    """detail: reason (NON_UTF8|BAD_HEADER|BAD_ROW_LENGTH|EMPTY), line."""

    code = "CSV_INVALID"


class ReviewRefused(SbomError):
    """detail: reason (contract section 4.13), line, row_id, column."""

    code = "READBACK_REFUSED"


class RepoFailure(SbomError):
    """Raised by per-repository units to fail one repository deliberately."""

    code = "REPO_FAILED"


class UsageError(SbomError):
    """Raised by cli_core's ArgumentParser.error() (exit code 2)."""

    code = "USAGE"


class OtherRunInFlight(SbomError):
    """A full run and a pilot run cannot be unfinished at the same time (they would share one conversation)."""

    code = "OTHER_RUN_IN_FLIGHT"


class NoSuchRepository(SbomError):
    """A pilot run was asked for a folder that is not a repository directly inside the workspace."""

    code = "NO_SUCH_REPOSITORY"


class NoRepositories(SbomError):
    """The workspace holds no git repository directly inside it. Retryable: the person can add or clone one and continue."""

    code = "NO_REPOSITORIES"
    retryable = True


def no_repositories_message(parent: object) -> str:
    return ("No git repository was found directly inside %s. Run the command from the folder whose subfolders are the "
            "repositories, add or clone them, then reply \"continue\"." % (parent,))
