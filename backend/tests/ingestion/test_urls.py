import pytest

from app.ingestion.url_validation import validate_repo_url


@pytest.mark.parametrize(
    ("url", "ref", "expected"),
    [
        (
            "https://github.com/example/repository",
            None,
            ("example", "repository", "https://github.com/example/repository", None),
        ),
        (
            "https://github.com/example/repository.git",
            "release/v1.0",
            ("example", "repository", "https://github.com/example/repository", "release/v1.0"),
        ),
    ],
)
def test_valid_repository_urls(url: str, ref: str | None, expected: tuple[str, ...]) -> None:
    repo = validate_repo_url(url, ref)
    assert (repo.owner, repo.name, repo.canonical_url, repo.requested_ref) == expected


@pytest.mark.parametrize(
    ("url", "ref"),
    [
        ("http://github.com/example/repository", None),
        ("https://github.com.evil.test/example/repository", None),
        ("https://github.com@evil.test/example/repository", None),
        ("https://user:secret@github.com/example/repository", None),
        ("https://github.com:443/example/repository", None),
        ("https://github.com/example/repository?token=secret", None),
        ("https://github.com/example/repository#fragment", None),
        ("https://github.com/example/repository/tree/main", None),
        ("https://github.com/example/%2e%2e", None),
        ("https://github.com/example/repository", "--upload-pack=evil"),
        ("https://github.com/example/repository", "../main"),
        ("https://github.com/example/repository", "refs//heads/main"),
        ("https://github.com/example/repository", "feature/.hidden"),
        ("https://github.com/example/repository\n--config=evil", None),
    ],
)
def test_unsafe_repository_inputs_are_rejected(url: str, ref: str | None) -> None:
    with pytest.raises(ValueError):
        validate_repo_url(url, ref)

