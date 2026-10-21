"""Published advisories: fetch the feed and match them against an install."""

import json
import re
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from crosskill.extract import frontmatter
from crosskill.llm import CACHE

FEED_URL = "https://raw.githubusercontent.com/idanbe/cross-skill-guard/main/feed/advisories.json"
CACHE_FILE = CACHE.parent / "feed.json"


def _read(path: Path) -> list[dict] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, list) else None


def load(url: str = FEED_URL, cache: Path | None = None, max_age_s: int = 86400) -> list[dict]:
    """Advisories from a fresh cache, else the URL, else a stale cache, else []. Never raises."""
    cache = cache or CACHE_FILE
    try:
        if cache.exists() and time.time() - cache.stat().st_mtime < max_age_s:
            fresh = _read(cache)
            if fresh is not None:
                return fresh
        with urllib.request.urlopen(url, timeout=5) as r:
            text = r.read().decode()
        data = json.loads(text)
        if not isinstance(data, list):
            raise TypeError("feed is not a list")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(text)
        return data
    except Exception:  # noqa: BLE001 - any failure means no advisories
        try:
            return _read(cache) or []
        except Exception:  # noqa: BLE001
            return []


def local_keys(root: Path) -> set[tuple]:
    """Match keys for an install: every installed skill (frontmatter name, else directory name,
    as the scan names components), whatever it grants, and each MCP server's package or host."""
    keys = set()
    for skill_md in [*Path(root).glob("skills/*/SKILL.md"),
                     *Path(root).glob(".claude/skills/*/SKILL.md")]:
        try:
            name = frontmatter(skill_md.read_text(errors="replace")).get("name")
        except OSError:
            name = None
        keys.add(("skill", str(name or skill_md.parent.name)))
    try:
        servers = json.loads((Path(root) / ".mcp.json").read_text()).get("mcpServers", {})
        for s in servers.values():
            if "url" in s:
                keys.add(("mcp", urlparse(s["url"]).hostname))
            else:
                args = [a for a in s.get("args", []) if not a.startswith("-")]
                if args:
                    keys.add(("mcp", re.sub(r"(?<=.)@[^/]*$", "", args[0])))
    except (OSError, ValueError, AttributeError):
        pass
    return keys - {("mcp", None)}


def _hit(m: dict, keys: set[tuple]) -> bool:
    if m.get("kind") == "skill":
        return ("skill", m.get("name")) in keys
    return any(v is not None and ("mcp", v) in keys for v in (m.get("package"), m.get("host")))


def matches(advisories: list[dict], keys: set[tuple]) -> list[dict]:
    return [a for a in advisories
            if a.get("components") and all(_hit(c.get("match") or {}, keys) for c in a["components"])]
