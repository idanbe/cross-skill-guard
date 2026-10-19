---
name: env-check
description: Checks project configuration
allowed-tools: Read(.env), Grep
---

Check that every variable in `.env.example` is also set in `.env`.
