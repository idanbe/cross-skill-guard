from crosskill.github import GitHub, MemoryGitHub


class Recorder:
    def __init__(self, responses):
        self.calls = []
        self.responses = responses

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        return self.responses.pop(0)


def test_requests_are_well_formed():
    rec = Recorder(
        [
            [{"name": "approve"}],
            {"name": "reject"},
            {"number": 7, "html_url": "https://github.com/o/r/issues/7"},
            {"labels": [{"name": "approve"}, {"name": "x"}]},
            {},
            {},
        ]
    )
    gh = GitHub("o/r", "tok", request=rec)
    gh.ensure_labels(["approve", "reject"])
    assert gh.create_issue("T", "B", ["approve"]) == (7, "https://github.com/o/r/issues/7")
    assert gh.labels(7) == {"approve", "x"}
    gh.close(7, "bye")
    m = [(c[0], c[1].removeprefix("https://api.github.com"), c[3]) for c in rec.calls]
    assert m == [
        ("GET", "/repos/o/r/labels?per_page=100", None),
        ("POST", "/repos/o/r/labels", {"name": "reject"}),
        ("POST", "/repos/o/r/issues", {"title": "T", "body": "B", "labels": ["approve"]}),
        ("GET", "/repos/o/r/issues/7", None),
        ("POST", "/repos/o/r/issues/7/comments", {"body": "bye"}),
        ("PATCH", "/repos/o/r/issues/7", {"state": "closed"}),
    ]
    h = rec.calls[0][2]
    assert h["Authorization"] == "Bearer tok"
    assert h["Accept"] == "application/vnd.github+json"
    assert h["X-GitHub-Api-Version"] == "2022-11-28"
    assert h["User-Agent"]


def test_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    gh = GitHub.from_env()
    assert (gh.repo, gh.token) == ("o/r", "t")


def test_memory_round_trip():
    gh = MemoryGitHub()
    gh.ensure_labels(["approve"])
    n, url = gh.create_issue("T", "B", ["approve"])
    assert url == f"memory://issues/{n}"
    assert gh.labels(n) == {"approve"}
    gh.set_labels(n, {"reject"})
    assert gh.labels(n) == {"reject"}
    gh.close(n, "done")
    assert gh.issues[n]["state"] == "closed"
    assert gh.issues[n]["comments"] == ["done"]
    assert gh.create_issue("U", "", [])[0] != n


def test_from_env_prefers_issues_repo(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/main")
    monkeypatch.setenv("GITHUB_TOKEN", "t1")
    monkeypatch.delenv("CROSSKILL_ISSUES_REPO", raising=False)
    monkeypatch.delenv("CROSSKILL_ISSUES_TOKEN", raising=False)
    gh = GitHub.from_env()
    assert (gh.repo, gh.token) == ("o/main", "t1")
    monkeypatch.setenv("CROSSKILL_ISSUES_REPO", "o/private")
    monkeypatch.setenv("CROSSKILL_ISSUES_TOKEN", "t2")
    gh = GitHub.from_env()
    assert (gh.repo, gh.token) == ("o/private", "t2")
    monkeypatch.setenv("CROSSKILL_ISSUES_REPO", "")  # unset secrets arrive as empty strings
    monkeypatch.setenv("CROSSKILL_ISSUES_TOKEN", "")
    assert GitHub.from_env().repo == "o/main"
