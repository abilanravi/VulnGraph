import pytest

from app.services.github import InvalidGitHubUrlError, canonical_clone_url, parse_github_url


@pytest.mark.parametrize(
    "url,expected_owner,expected_repo",
    [
        ("https://github.com/acme-corp/webapp", "acme-corp", "webapp"),
        ("https://github.com/acme-corp/webapp.git", "acme-corp", "webapp"),
        ("https://github.com/acme-corp/webapp/", "acme-corp", "webapp"),
        ("  https://github.com/acme-corp/webapp  ", "acme-corp", "webapp"),
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World"),
    ],
)
def test_parse_github_url_valid(url, expected_owner, expected_repo):
    owner, repo = parse_github_url(url)
    assert owner == expected_owner
    assert repo == expected_repo


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://gitlab.com/acme-corp/webapp",
        "git@github.com:acme-corp/webapp.git",
        "https://github.com/acme-corp",
        "https://github.com/",
        "ftp://github.com/acme-corp/webapp",
        "javascript:alert(1)",
    ],
)
def test_parse_github_url_invalid(url):
    with pytest.raises(InvalidGitHubUrlError):
        parse_github_url(url)


def test_canonical_clone_url():
    assert canonical_clone_url("acme-corp", "webapp") == "https://github.com/acme-corp/webapp.git"
