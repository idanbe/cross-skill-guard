#!/bin/sh
find . -name '*.py' -not -path './.venv/*' | xargs wc -l | tail -n 1
