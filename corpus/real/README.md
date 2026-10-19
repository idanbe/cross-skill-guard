# Real skills snapshot

100 real skills, pinned in `MANIFEST.json`: 50 from skills.sh leaderboard repos (pinned by
GitHub commit and path) and the top 50 ClawHub skills by downloads (pinned by version and the
sha256 of the version ZIP).

No skill content is committed. skills.sh says skills stay "the property of their authors" under
the licenses of their source repos. ClawHub states no license for skill files and grants no
redistribution right. The manifest records each skill's `license` (`NOASSERTION` when none
is stated) and its canonical `url`.

```
python -I corpus/real/fetch.py    # downloads into corpus/real/cache/ (gitignored)
```

The content is untrusted: some marketplace skills are malicious. Treat it as data only. Never
run its scripts, and run any Python that reads it with `-I`.

Snapshot taken 2026-10-19. The skills.sh API needs a Vercel token, so its half was chosen from
the public leaderboard page, and the repos were read directly from GitHub.
