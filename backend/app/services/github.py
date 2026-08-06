"""Parses and validates GitHub repository URLs.

Only `https://github.com/<owner>/<repo>` (optionally with a trailing `.git` or `/`) is
supported — no SSH URLs, no other Git hosts. Keeping the accepted shape narrow means the
canonical HTTPS clone URL can always be reconstructed from `owner` + `repo` alone (see
app/services/repo_fetch.py), rather than cloning whatever string a user pasted in.
"""

import re

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


class InvalidGitHubUrlError(ValueError):
    """Raised when a string is not a supported GitHub repository URL."""


def parse_github_url(url: str) -> tuple[str, str]:
    """Extracts (owner, repo) from a GitHub repository URL, or raises InvalidGitHubUrlError."""
    match = _GITHUB_URL_RE.match(url.strip())
    if not match:
        raise InvalidGitHubUrlError(
            "Not a valid GitHub repository URL. Expected https://github.com/<owner>/<repo>."
        )
    return match.group("owner"), match.group("repo")


def canonical_clone_url(owner: str, repo: str) -> str:
    """Builds the canonical HTTPS clone URL for a public GitHub repository."""
    return f"https://github.com/{owner}/{repo}.git"
