import json
import shutil
from pathlib import Path

from crosskill.extract import extract, is_private

POPULAR = Path(__file__).parent / "fixtures" / "popular-mcp.json"
NAMES = {"filesystem", "fetch", "playwright", "github", "postgres", "sqlite", "slack",
         "brave-search", "puppeteer", "gdrive"}


def test_popular_mcp_grants(tmp_path):
    shutil.copy(POPULAR, tmp_path / ".mcp.json")
    servers = json.loads(POPULAR.read_text())["mcpServers"]
    assert set(servers) == NAMES
    lines = POPULAR.read_text().splitlines()
    grants = extract(tmp_path)
    for name, server in servers.items():
        mine = [g for g in grants if g.rule == f"mcp__{name}"]
        assert mine, name
        line = next(i for i, ln in enumerate(lines, 1) if f'"{name}"' in ln)
        assert {g.line for g in mine} == {line}
        assert isinstance(server["x-crosskill"]["installs"], int) and server["x-crosskill"]["url"]
    slack = [(g.kind, g.arg) for g in grants if g.rule == "mcp__slack"]
    assert ("egress", "slack.com") in slack and ("reads", "slack") in slack


def test_new_private_resources():
    assert is_private("slack") and is_private("gdrive")
