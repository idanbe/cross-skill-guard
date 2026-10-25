"""Permission audit: find the program a Bash command really runs behind wrappers and shells."""

import itertools
import os
from collections.abc import Iterator

import bashlex
from bashlex.errors import ParsingError

from crosskill.extract import ARBITRARY, NETWORK

DOWNLOADERS = {"npx"}  # runs arbitrary downloaded code, so it is the finding itself
SHELLS = {"sh", "bash", "zsh"}
# Runner -> subcommands that run a command. Options (and mise TOOL@VER args) are skipped, then
# POSITIONAL words (docker container, direnv dir) before the command itself.
RUNNERS = {"devbox": {"run"}, "mise": {"exec", "x"}, "docker": {"exec"}, "direnv": {"exec"}}
POSITIONAL = {"docker": 1, "direnv": 1}


def verify(command: str) -> str | None:
    """The arbitrary or network program that the command runs, or None."""
    try:
        nodes = bashlex.parse(command)
    except (ParsingError, AttributeError, TypeError):  # bashlex raises these on bad input
        return None
    for words in _commands(nodes):
        hit = _resolve(words)
        if hit:
            return hit
    return None


def _commands(nodes: list) -> Iterator[list[str]]:
    for node in nodes:
        if node.kind == "command":
            yield [part.word for part in node.parts if part.kind == "word"]
        yield from _commands(getattr(node, "parts", []) + getattr(node, "list", []))


def _resolve(words: list[str]) -> str | None:
    if not words:
        return None
    prog = os.path.basename(words[0])
    if prog in DOWNLOADERS:
        return prog
    inner = None
    if prog in SHELLS and words[1:2] == ["-c"] and len(words) > 2:
        inner = verify(words[2])
    elif prog == "git":
        for flag, value in itertools.pairwise(words):
            if flag == "-c" and value.startswith("core.sshCommand="):
                inner = verify(value.split("=", 1)[1])
                break
    elif prog in RUNNERS:
        inner = _resolve(_runner_command(prog, words[1:]))
    if inner:
        return inner
    for name in (" ".join([prog, *words[1:2]]), prog):  # "pip install" is one entry
        if name in ARBITRARY | NETWORK:
            return name
    return None


def _runner_command(prog: str, args: list[str]) -> list[str]:
    """The words a runner runs after its subcommand, or [] when the subcommand does not run one."""
    if not args or args[0] not in RUNNERS[prog]:
        return []
    rest = args[1:]
    i = 0
    while i < len(rest) and (rest[i].startswith("-") or (prog == "mise" and "@" in rest[i])):
        i += 1
    return rest[i + POSITIONAL.get(prog, 0):]
