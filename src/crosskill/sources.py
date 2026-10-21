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
MAX_ZIP_BYTES = 20 * 1024 * 1024  # uncompressed, all members together
MAX_ZIP_MEMBERS = 2000


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
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == 4:
                raise  # a 429 left over is transient: the daily run stops and retries next run
            wait = e.headers.get("Retry-After", "5")
            time.sleep(min(int(wait), 60) if wait.isdigit() else 5)
    raise AssertionError("unreachable")


def http_json(url: str) -> dict:
    return json.loads(http_bytes(url))


def _skill(it: dict) -> Skill:
    owner, slug = it["ownerHandle"], it["slug"]
    version = (it.get("latestVersion") or {}).get("version") or it["tags"]["latest"]
    return Skill(owner, slug, version, int(it["stats"].get("installs", 0)),
                 int(it["updatedAt"]), f"https://clawhub.ai/{owner}/skills/{slug}")


def _pages(sort: str, get, max_pages: int, seen: dict):
    """Listing items, page by page. Sets seen["truncated"] when max_pages ends it early."""
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
    seen["truncated"] = True


def _parse(it, notes: list[str]) -> Skill | None:
    """A Skill, or None (logged in notes) for an item without the fields one needs."""
    try:
        return _skill(it)
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        name = f"{it.get('ownerHandle')}/{it.get('slug')}" if isinstance(it, dict) else repr(it)[:60]
        notes.append(f"listing: skipped item {name}: {e!r}")
        return None


def updated_since(after_ms: int, limit: int, get=http_json, max_pages: int = 100,
                  notes: list[str] | None = None) -> list[Skill]:
    """The oldest `limit` skills updated after `after_ms`, oldest first.

    Malformed items are skipped with a line in `notes`; so is hitting `max_pages` before reaching
    `after_ms` ("listing truncated"): skills older than the last page are then never seen."""
    notes = [] if notes is None else notes
    out: list[Skill] = []
    seen: dict = {}
    for it in _pages("updated", get, max_pages, seen):
        sk = _parse(it, notes)
        if sk is None:
            continue
        if sk.updated_at <= after_ms:
            break
        out.append(sk)
    else:
        if seen.get("truncated"):
            notes.append(f"listing truncated: {max_pages} pages read before reaching the cursor; "
                         "older updated skills are missed")
    return sorted(out, key=lambda s: s.updated_at)[:limit]


def popular(n: int = 200, get=http_json, max_pages: int = 100,
            notes: list[str] | None = None) -> list[Skill]:
    notes = [] if notes is None else notes
    out: list[Skill] = []
    for it in _pages("downloads", get, max_pages, {}):
        if len(out) >= n:
            break
        if (sk := _parse(it, notes)) is not None:
            out.append(sk)
    return out


class TooLarge(ValueError):
    """A skill ZIP over the size or member cap: a deterministic failure for that skill."""


def download(skill: Skill, dest: Path, get_bytes=http_bytes) -> Path:
    """Extract the skill ZIP into dest/<dirname>, skipping members that leave it and symlinks.

    At most MAX_ZIP_MEMBERS members and MAX_ZIP_BYTES uncompressed (declared sizes checked first,
    bytes written counted too); over either cap, nothing is kept and TooLarge is raised."""
    q = urllib.parse.urlencode({"slug": skill.slug, "owner": skill.owner,
                                "version": skill.version})
    data = get_bytes(f"{API}/download?{q}")
    target = (dest / skill.dirname).resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        members = z.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise TooLarge(f"{skill.id}: {len(members)} ZIP members (cap {MAX_ZIP_MEMBERS})")
        declared = sum(m.file_size for m in members)
        if declared > MAX_ZIP_BYTES:
            raise TooLarge(f"{skill.id}: {declared} bytes uncompressed (cap {MAX_ZIP_BYTES})")
        target.mkdir(parents=True, exist_ok=True)
        try:
            written = 0
            for m in members:
                if m.is_dir() or (m.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                path = (target / m.filename).resolve()
                if not path.is_relative_to(target) or path == target:
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                with z.open(m) as src, open(path, "wb") as out:
                    while chunk := src.read(65536):
                        written += len(chunk)
                        if written > MAX_ZIP_BYTES:
                            raise TooLarge(f"{skill.id}: over {MAX_ZIP_BYTES} bytes written")
                        out.write(chunk)
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)  # never leave a partial skill for reuse
            raise
    return target
