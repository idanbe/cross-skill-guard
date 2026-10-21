"""Minimal GitHub issues client (stdlib only) and an in-memory stand-in for tests and dry runs."""

import json
import os
import urllib.request

API = "https://api.github.com"


def urlopen_json(method: str, url: str, headers: dict, body: dict | None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


class GitHub:
    def __init__(self, repo: str, token: str, request=urlopen_json):
        self.repo = repo
        self.token = token
        self.request = request

    @classmethod
    def from_env(cls) -> "GitHub":
        return cls(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])

    def _call(self, method: str, path: str, body: dict | None = None):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "crosskill-feed",
        }
        return self.request(method, f"{API}/repos/{self.repo}{path}", headers, body)

    def ensure_labels(self, names: list[str]) -> None:
        have = {label["name"] for label in self._call("GET", "/labels?per_page=100")}
        for name in names:
            if name not in have:
                self._call("POST", "/labels", {"name": name})

    def create_issue(self, title: str, body: str, labels: list[str]) -> tuple[int, str]:
        r = self._call("POST", "/issues", {"title": title, "body": body, "labels": labels})
        return r["number"], r["html_url"]

    def labels(self, number: int) -> set[str]:
        return {label["name"] for label in self._call("GET", f"/issues/{number}")["labels"]}

    def close(self, number: int, comment: str) -> None:
        self._call("POST", f"/issues/{number}/comments", {"body": comment})
        self._call("PATCH", f"/issues/{number}", {"state": "closed"})


class MemoryGitHub:
    def __init__(self):
        self.issues: dict[int, dict] = {}
        self.known_labels: set[str] = set()

    def ensure_labels(self, names: list[str]) -> None:
        self.known_labels |= set(names)

    def create_issue(self, title: str, body: str, labels: list[str]) -> tuple[int, str]:
        n = len(self.issues) + 1
        self.issues[n] = {
            "title": title,
            "body": body,
            "labels": set(labels),
            "state": "open",
            "comments": [],
        }
        return n, f"memory://issues/{n}"

    def labels(self, number: int) -> set[str]:
        return set(self.issues[number]["labels"])

    def close(self, number: int, comment: str) -> None:
        self.issues[number]["comments"].append(comment)
        self.issues[number]["state"] = "closed"

    def set_labels(self, number: int, labels) -> None:
        self.issues[number]["labels"] = set(labels)
