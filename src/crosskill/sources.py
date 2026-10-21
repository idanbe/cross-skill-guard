"""ClawHub source: list new and popular skills and download them as data (never executed)."""

import io
import json
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

API = "https://clawhub.ai/api/v1"


@dataclass
class Skill:
    owner: str
    slug: str
    version: str
    installs: int
    updated_at: int
    url: str

    @property
    def id(self) -> str:
        return f"clawhub/{self.owner}/{self.slug}"

    @property
    def dirname(self) -> str:
        return f"{self.owner}--{self.slug}"


def http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "crosskill-feed"})
    for _ in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            time.sleep(int(e.headers.get("Retry-After", "5")))
    raise RuntimeError(f"rate limited: {url}")


def http_json(url: str) -> dict:
    return json.loads(http_bytes(url))


def _skill(it: dict) -> Skill:
    owner, slug = it["ownerHandle"], it["slug"]
    version = (it.get("latestVersion") or {}).get("version") or it["tags"]["latest"]
    return Skill(owner, slug, version, int(it["stats"].get("installs", 0)),
                 int(it["updatedAt"]), f"https://clawhub.ai/{owner}/skills/{slug}")


def _pages(sort: str, get, max_pages: int = 100):
    cursor = None
    for _ in range(max_pages):
        url = f"{API}/skills?sort={sort}&limit=100"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        page = get(url)
        yield from page["items"]
        cursor = page.get("nextCursor")
        if not cursor:
            return


def updated_since(after_ms: int, limit: int, get=http_json, max_pages: int = 100) -> list[Skill]:
    """The oldest `limit` skills updated after `after_ms`, oldest first."""
    out: list[Skill] = []
    for it in _pages("updated", get, max_pages):
        if int(it["updatedAt"]) <= after_ms:
            break
        out.append(_skill(it))
    return sorted(out, key=lambda s: s.updated_at)[:limit]


def popular(n: int = 200, get=http_json, max_pages: int = 100) -> list[Skill]:
    out: list[Skill] = []
    for it in _pages("downloads", get, max_pages):
        if len(out) >= n:
            break
        out.append(_skill(it))
    return out


def download(skill: Skill, dest: Path, get_bytes=http_bytes) -> Path:
    """Extract the skill ZIP into dest/<dirname>, skipping members that leave it and symlinks."""
    q = urllib.parse.urlencode({"slug": skill.slug, "owner": skill.owner,
                                "version": skill.version})
    data = get_bytes(f"{API}/download?{q}")
    target = (dest / skill.dirname).resolve()
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for m in z.infolist():
            if m.is_dir() or (m.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            path = (target / m.filename).resolve()
            if not path.is_relative_to(target) or path == target:
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(m) as src, open(path, "wb") as out:
                shutil.copyfileobj(src, out)
    return target
