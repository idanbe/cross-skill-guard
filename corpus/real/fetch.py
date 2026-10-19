"""Download the skills pinned in MANIFEST.json into corpus/real/cache/ (gitignored).

The content is third-party and untrusted: it is extracted as data and never executed.
Run with `python -I corpus/real/fetch.py`.
"""

import hashlib
import io
import json
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
CACHE = HERE / "cache"


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "crosskill-corpus"})
    for _ in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            time.sleep(int(e.headers.get("Retry-After", "5")))
    raise RuntimeError(f"rate limited: {url}")


def main() -> None:
    entries = json.loads((HERE / "MANIFEST.json").read_text())["skills"]
    tarballs: dict[tuple[str, str], bytes] = {}
    for e in entries:
        dest = CACHE / e["id"]
        if dest.exists():
            continue
        if e["source"] == "skills.sh":
            key = (e["repo"], e["commit"])
            if key not in tarballs:
                tarballs[key] = get(f"https://codeload.github.com/{key[0]}/tar.gz/{key[1]}")
            with tarfile.open(fileobj=io.BytesIO(tarballs[key])) as tar:
                prefix = tar.getmembers()[0].name.split("/")[0] + "/" + e["path"] + "/"
                members = [m for m in tar.getmembers() if m.name.startswith(prefix)]
                for m in members:
                    m.name = m.name[len(prefix):]
                tar.extractall(dest, members=members, filter="data")
        else:
            data = get(f"https://clawhub.ai/api/v1/download?slug={e['slug']}"
                       f"&owner={e['owner']}&version={e['version']}")
            if hashlib.sha256(data).hexdigest() != e["sha256"]:
                raise SystemExit(f"sha256 mismatch: {e['id']}")
            zipfile.ZipFile(io.BytesIO(data)).extractall(dest)
            time.sleep(0.2)
        print("fetched", e["id"])


if __name__ == "__main__":
    main()
