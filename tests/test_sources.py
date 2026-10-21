import io
import zipfile

from crosskill import sources


def item(owner, slug, updated, installs=1, version="1.0.0"):
    return {"ownerHandle": owner, "slug": slug, "displayName": slug, "summary": "",
            "latestVersion": {"version": version}, "tags": {"latest": version},
            "stats": {"downloads": 5, "installs": installs, "stars": 0},
            "createdAt": 1, "updatedAt": updated}


def fake_get(pages):
    calls = []

    def get(url):
        calls.append(url)
        return pages[len(calls) - 1]
    get.calls = calls
    return get


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_updated_since_pages_and_stops():
    get = fake_get([
        {"items": [item("a", "s5", 500), item("a", "s4", 400)], "nextCursor": "c1"},
        {"items": [], "nextCursor": "c2"},
        {"items": [item("b", "s3", 300), item("b", "s2", 200), item("b", "s1", 100)],
         "nextCursor": "c3"},
    ])
    out = sources.updated_since(200, 50, get=get)
    assert [s.slug for s in out] == ["s3", "s4", "s5"]
    assert len(get.calls) == 3
    assert "sort=updated" in get.calls[0] and "cursor=c1" in get.calls[1]


def test_updated_since_respects_limit():
    get = fake_get([{"items": [item("a", f"s{i}", 900 - i) for i in range(5)],
                     "nextCursor": None}])
    out = sources.updated_since(0, 2, get=get)
    assert [x.slug for x in out] == ["s4", "s3"]


def test_updated_since_caps_pages():
    page = {"items": [], "nextCursor": "same"}
    get = fake_get([page] * 10)
    assert sources.updated_since(0, 5, get=get, max_pages=3) == []
    assert len(get.calls) == 3


def test_popular_reads_installs():
    get = fake_get([{"items": [item("a", "x", 10, installs=42, version="2.1.0")],
                     "nextCursor": None}])
    [s] = sources.popular(5, get=get)
    assert "sort=downloads" in get.calls[0]
    assert (s.owner, s.slug, s.version, s.installs, s.updated_at) == ("a", "x", "2.1.0", 42, 10)
    assert s.id == "clawhub/a/x" and s.dirname == "a--x"
    assert s.url == "https://clawhub.ai/a/skills/x"


def test_download_extracts_inside_dest(tmp_path):
    s = sources.Skill("a", "x", "1.0.0", 1, 1, "u")
    seen = []

    def get_bytes(url):
        seen.append(url)
        return make_zip({"SKILL.md": "hi", "scripts/run.sh": "echo"})
    d = sources.download(s, tmp_path, get_bytes=get_bytes)
    assert d == tmp_path / "a--x"
    assert (d / "SKILL.md").read_text() == "hi"
    assert (d / "scripts" / "run.sh").exists()
    assert "slug=x" in seen[0] and "owner=a" in seen[0] and "version=1.0.0" in seen[0]


def test_download_skips_traversal_members(tmp_path):
    s = sources.Skill("a", "x", "1.0.0", 1, 1, "u")
    data = make_zip({"../evil": "x", "/abs/evil": "x", "ok.md": "ok"})
    d = sources.download(s, tmp_path, get_bytes=lambda url: data)
    assert (d / "ok.md").exists()
    assert not (tmp_path / "evil").exists()
    assert not (d.parent / "evil").exists()
    assert sorted(p.name for p in d.rglob("*") if p.is_file()) == ["ok.md"]
