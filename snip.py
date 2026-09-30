#!/usr/bin/env -S pipx run
# /// script
# requires-python = ">=3.11"
# dependencies = ["cyclopts>=3", "rich>=13"]
# ///
"""snip: read-only snippet lookup. Add snippets by editing SNIPPETS below."""
from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from difflib import get_close_matches
from typing import Annotated
import tempfile
from pathlib import Path

from cyclopts import App, Parameter
from rich.console import Console
from rich.prompt import IntPrompt, Prompt
from rich.syntax import Syntax
from rich.table import Table

# ── snippets ────────────────────────────────────────────────────────────────
# TOML. Use '''...''' (literal strings) for bodies: no escaping needed.
# A body containing three single quotes would need """...""" instead, and
# then the outer Python string must use ''' (or vice versa).
SNIPPETS = r"""
[curl-retry]
description = "curl with retries and sane failure behaviour"
lang = "bash"
tags = ["http", "shell"]
body = '''
curl --fail --silent --show-error --location \
     --retry 5 --retry-all-errors {{url}}
'''

[git-undo-commit]
description = "undo last commit, keep changes staged"
lang = "bash"
tags = ["git"]
body = '''
git reset --soft HEAD~1
'''

[py-dataclass]
description = "dataclass skeleton"
lang = "python"
tags = ["python"]
body = '''
from dataclasses import dataclass, field

@dataclass(slots=True)
class {{name}}:
    id: int
    tags: list[str] = field(default_factory=list)
'''
"""
# ────────────────────────────────────────────────────────────────────────────

DB: dict[str, dict] = tomllib.loads(SNIPPETS)
PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")
err = Console(stderr=True)
out = Console()

app = App(name="snip", help=__doc__, version="0.1.0")


def candidates(query: str) -> list[str]:
    """exact -> prefix -> substring -> fuzzy; the first non-empty tier wins."""
    q = query.lower()
    names = list(DB)
    if q in DB:
        return [q]
    for tier in (
        [n for n in names if n.lower().startswith(q)],
        [n for n in names if q in n.lower()],
        get_close_matches(q, names, n=8, cutoff=0.5),
    ):
        if tier:
            return tier
    return []


def pick(names: list[str]) -> str:
    if shutil.which("fzf") and sys.stdin.isatty():
        with tempfile.TemporaryDirectory() as tmp:
            # index-based filenames, so odd characters in snippet names are safe
            for i, n in enumerate(names):
                (Path(tmp) / str(i)).write_text(DB[n]["body"])
            lines = "\n".join(
                f"{i}\t{n}\t{DB[n].get('description', '')}" for i, n in enumerate(names)
            )
            r = subprocess.run(
                [
                    "fzf",
                    "--delimiter=\t",
                    "--with-nth=2,3",
                    "--preview",
                    f"cat {shlex.quote(tmp)}/{{1}}",
                    "--preview-window=right,60%",
                ],
                input=lines,
                text=True,
                stdout=subprocess.PIPE,
            )
        if r.returncode != 0:
            raise SystemExit(1)
        return r.stdout.split("\t")[1]
    for i, n in enumerate(names, 1):
        err.print(
            f"[cyan]{i:>2}[/] [bold]{n}[/]  [dim]{DB[n].get('description', '')}[/]"
        )
    choice = IntPrompt.ask(
        "pick", console=err, choices=[str(i) for i in range(1, len(names) + 1)]
    )
    return names[choice - 1]


def render(body: str, values: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in values:
            values[key] = Prompt.ask(f"[yellow]{key}[/]", console=err)
        return values[key]

    return PLACEHOLDER.sub(sub, body)


@app.default
def get(
    query: str | None = None,
    *,
    set_: Annotated[
        list[str] | None,
        Parameter(
            name=["--set", "-s"], negative_iterable="", help="fill {{key}} as key=value"
        ),
    ] = None,
    raw: Annotated[
        bool, Parameter(negative="", help="no templating, no highlighting")
    ] = False,
) -> None:
    """Print a snippet to stdout (opens a picker if the match is ambiguous).

    Parameters
    ----------
    query
        Name or partial name of the snippet. Omit to browse all.
    """
    names = candidates(query) if query else list(DB)
    if not names:
        err.print(f"[red]no snippet matching[/] {query!r}")
        raise SystemExit(1)
    name = names[0] if len(names) == 1 else pick(names)
    snip = DB[name]
    body = snip["body"]
    if not raw:
        try:
            values = dict(kv.split("=", 1) for kv in (set_ or []))
        except ValueError:
            err.print("[red]--set expects key=value[/]")
            raise SystemExit(2)
        body = render(body, values)
    if raw or not sys.stdout.isatty():
        sys.stdout.write(body)
    else:
        out.print(
            Syntax(body, snip.get("lang", "text"), theme="ansi_dark", word_wrap=True)
        )


@app.command(name="ls")
def list_snippets(
    *, tag: Annotated[str | None, Parameter(name=["--tag", "-t"])] = None
) -> None:
    """List snippets, optionally filtered by tag."""
    t = Table(box=None, header_style="bold")
    for col in ("name", "lang", "tags", "description"):
        t.add_column(col)
    for n, s in sorted(DB.items()):
        if tag and tag not in s.get("tags", []):
            continue
        t.add_row(
            n, s.get("lang", ""), ",".join(s.get("tags", [])), s.get("description", "")
        )
    out.print(t)  # stdout: Rich drops colour automatically when piped


if __name__ == "__main__":
    app()
