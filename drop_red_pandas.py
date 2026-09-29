"""dropkit -- quick bootstrap for fresh Kali / HTB pwnbox environments.

Typer + Rich CLI. Installs selected tools/configs in parallel.
Run non-interactively with --tools, or interactively with no args.

    dropkit --list
    dropkit --tools ligolo,vimrc -y
    dropkit --all -j 6
    dropkit                 # interactive picker
"""

# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "typer>=0.12.0",
#     "rich>=13.0.0",
#     "dotenv>=0.9.9",
# ]
# ///

from __future__ import annotations

from io import UnsupportedOperation
import json
import os
import shutil
import subprocess
import tarfile
import time
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Callable, Optional
from dotenv import dotenv_values

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

BANNER = r"""
                      █      █           █                   
                       ██    █  █       █                    
                       █         ██████  █                   
                                    █   █                    
  ██    ███                             █          ██    ██  
█           ██          █              █       ██            
         ██    █        █              █     █     █         
█     █████  █   ██   ███             █    █   █  █████     █
    █    █████ █   ███████  █        █████   █ █████    █    
        ██   ██  █ ███████████████████████ █  ██   ██        
█              █ ███████████████████████████ █      █   █   █
      █      █ ███████████████████████████████        █      
██         ██████████████████████████████████████          ██
█     ███████████████████████████████████████████████████   █
█ █     █ █████████████████████████████████████████ █     █ █
 █   █   ████████████████  ███████   ███████████████   ██  █ 
   ██   ███████████████     ██████    ███████████████   ██   
 ██    ██████████████████   ██████  ██████████████████    ██ 
██ ██ ██████████████  ██ ███████████ ███  ████████████████ ██
    ███████     ███ ██████ █     ██ ██████ ██     ███████    
   ███████     █████ ████ █        █ ███  ████      ██████   
     ████      █████████             ██████████     ████     
     ████     ███████                    ██████     ████     
      ███     █████  █     ████████     █ ██████    ████     
     █████    █████       █████████  █     █████   █████     
     ██████   █████        ████████       ███ █   ██████     
     ██ █████  ██████         █          █████  █████ ██     
       ████████  █████ ██  ██   ██  ███ ████  ████████       
           ████████                        ███████           
               █████████             █████████               
                    █████████    ████████                    
"""


important_values_after_install: dict[str, str] = {}


def print_banner() -> None:
    console.print(BANNER, style="red", markup=False, highlight=False)


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #
import platform

ARCH_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm",
}


def get_target() -> tuple[str, str]:
    os_name = platform.system().lower()  # linux / darwin / windows
    raw_arch = platform.machine().lower()
    arch = ARCH_ALIASES.get(raw_arch, raw_arch)
    return os_name, arch


def detect_distro() -> str:
    """Distinguish Debian-family distros: 'kali', 'ubuntu', or 'debian'.

    platform.system() reports only 'linux' for all three, so the canonical
    source is the ID field in /etc/os-release (systemd standard, present on
    modern Kali/Ubuntu/Debian). Returns the raw id or 'unknown' otherwise.
    """
    fields: dict[str, str] = {}
    osr = Path("/etc/os-release")
    if osr.exists():
        for line in osr.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            fields[key] = val.strip().strip('"').strip("'")

    distro_id = fields.get("ID", "").lower()
    if distro_id in {"kali", "ubuntu", "debian"}:
        return distro_id

    # Fallbacks for images with a missing/renamed ID.
    like = fields.get("ID_LIKE", "").lower()
    pretty = fields.get("PRETTY_NAME", "").lower()
    if "kali" in pretty:
        return "kali"
    if "ubuntu" in pretty or "ubuntu" in like:
        return "ubuntu"
    if "debian" in like or Path("/etc/debian_version").exists():
        return "debian"
    return distro_id or "unknown"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

HOME = Path.home()
LOCAL_BIN = HOME / ".local" / "bin"


def is_root() -> bool:
    return getattr(os, "geteuid", lambda: 1)() == 0


def sudo_prefix() -> list[str]:
    """Prefix to run a command as root.

    Empty when already root. Otherwise `sudo -n` (non-interactive) -- it relies
    on credentials cached earlier by ensure_sudo(); it never prompts, so it is
    safe to call from parallel worker threads.
    """
    if is_root():
        return []
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    raise RuntimeError("root required but 'sudo' not available")


def sh(
    cmd: list[str],
    report: Optional[Callable[[str], None]] = None,
    sudo: bool = False,
    cwd: Optional[Path] = None,
) -> None:
    full = sudo_prefix() + cmd if sudo else cmd
    if report:
        where = f"  (cwd={cwd})" if cwd else ""
        report(f"$ {' '.join(full)}{where}")
    subprocess.run(
        full,
        check=True,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


def download(
    url: str, dest: Path, report: Optional[Callable[[str], None]] = None
) -> None:
    if report:
        report(f"downloading {url.split('/')[-1]}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "dropkit"})
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def github_latest_asset(repo: str, must_contain: list[str], report=None) -> str:
    """browser_download_url of the latest release asset matching all substrings."""
    if report:
        report("resolving latest release")
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        api, headers={"User-Agent": "dropkit", "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.load(r)
    for asset in data.get("assets", []):
        name = asset["name"].lower()
        if all(s in name for s in must_contain):
            return asset["browser_download_url"]
    raise RuntimeError(f"no asset for {repo} matching {must_contain}")


def has_docker() -> bool:
    return shutil.which("docker") is not None


def has_compose_plugin() -> bool:
    """True if the Docker Compose v2 plugin (`docker compose`) is available."""
    if not has_docker():
        return False
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _docker_cmd(args: list[str], sudo: bool) -> list[str]:
    prefix = sudo_prefix() if sudo else []
    return prefix + ["docker", *args]


def has_docker() -> bool:
    return shutil.which("docker") is not None


def has_compose_plugin(sudo: bool = False) -> bool:
    """True if the Docker Compose v2 plugin (`docker compose`) is available."""
    if not has_docker():
        return False
    try:
        if sudo:
            sh(["sudo", "docker", "compose", "version"], sudo=True)
        else:
            sh(["docker", "compose", "version"], sudo=False)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def docker_ready(sudo: bool = False) -> bool:
    try:
        if sudo:
            sh(["sudo", "docker", "info"], sudo=True)
        else:
            sh(["docker", "info"], sudo=False)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def wait_for_docker(
    timeout: float = 30.0,
    interval: float = 1.0,
    sudo: bool = False,
    report: Optional[Callable[[str], None]] = None,
) -> bool:
    """Poll until the docker daemon responds, or timeout seconds elapse."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if docker_ready(sudo=sudo):
            return True
        if report:
            report("waiting for docker daemon...")
        time.sleep(interval)
    return False


ALIAS_MARKER_START = "# >>> dropkit aliases >>>"
ALIAS_MARKER_END = "# <<< dropkit aliases <<<"


def _shell_rc_files() -> list[Path]:
    """rc files to update, in priority order. Only returns ones that exist
    or whose parent shell is plausibly in use (bash always gets one)."""
    candidates = [HOME / ".bashrc", HOME / ".zshrc"]
    return [p for p in candidates if p.exists()] or [HOME / ".bashrc"]


def add_alias(
    name: str, command: str, report: Optional[Callable[[str], None]] = None
) -> None:
    """Add one alias to a managed block in each shell rc file. Idempotent --
    re-running updates the value instead of duplicating the line.
    """
    line = f"alias {name}={command!r}"
    for rc in _shell_rc_files():
        text = rc.read_text() if rc.exists() else ""
        if ALIAS_MARKER_START not in text:
            block = f"\n{ALIAS_MARKER_START}\n{ALIAS_MARKER_END}\n"
            text += block

        start = text.index(ALIAS_MARKER_START)
        end = text.index(ALIAS_MARKER_END)
        block_lines = text[start:end].splitlines()

        # drop any existing alias with this name, then append the new one
        block_lines = [l for l in block_lines if not l.startswith(f"alias {name}=")]
        block_lines.append(line)

        new_block = "\n".join(block_lines) + "\n"
        text = text[:start] + new_block + text[end:]
        rc.write_text(text)
        if report:
            report(f"alias {name} -> {rc.name}")


def add_aliases(
    aliases: dict[str, str], report: Optional[Callable[[str], None]] = None
) -> None:
    """Bulk version -- {name: command}."""
    for name, command in aliases.items():
        add_alias(name, command, report)


def remove_all_aliases(report: Optional[Callable[[str], None]] = None) -> None:
    """Strip the whole managed block from every rc file (clean uninstall)."""
    for rc in _shell_rc_files():
        if not rc.exists():
            continue
        text = rc.read_text()
        if ALIAS_MARKER_START not in text:
            continue
        start = text.index(ALIAS_MARKER_START)
        end = text.index(ALIAS_MARKER_END) + len(ALIAS_MARKER_END)
        text = (
            text[:start] + text[end + 1 :]
            if text[end : end + 1] == "\n"
            else text[:start] + text[end:]
        )
        rc.write_text(text)
        if report:
            report(f"removed alias block from {rc.name}")


# --------------------------------------------------------------------------- #
# Installers
# --------------------------------------------------------------------------- #
def install_ligolo(report: Callable[[str], None]) -> None:
    os_name, arch = get_target()
    url = github_latest_asset(
        "nicocha30/ligolo-ng",
        must_contain=["agent", os_name, arch, ".tar.gz"],
        report=report,
    )
    with tempfile.TemporaryDirectory() as td:
        tarball = Path(td) / "ligolo.tar.gz"
        download(url, tarball, report)
        report("extracting")
        with tarfile.open(tarball) as tf:
            tf.extractall(td)
        LOCAL_BIN.mkdir(parents=True, exist_ok=True)
        binary = next(Path(td).glob("**/agent*"))
        dest = LOCAL_BIN / "ligolo-agent"
        shutil.copy2(binary, dest)
        dest.chmod(0o755)
    report(f"-> {dest}")


def install_linenum(report: Callable[[str], None]) -> None:
    """Example 'install from GitHub (clone)' installer.

    Shallow-clone a repo, keep it updatable on re-runs, and expose the script
    on PATH via a symlink. No root needed -- everything stays under $HOME.
    """
    dest = HOME / ".local" / "share" / "LinEnum"
    if dest.exists():
        report("updating repo")
        sh(["git", "-C", str(dest), "pull", "--ff-only"], report)
    else:
        report("cloning rebootuser/LinEnum")
        dest.parent.mkdir(parents=True, exist_ok=True)
        sh(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "https://github.com/rebootuser/LinEnum",
                str(dest),
            ],
            report,
        )
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    link = LOCAL_BIN / "LinEnum.sh"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(dest / "LinEnum.sh")
    report(f"-> {link}")


def install_ripgrep(report: Callable[[str], None]) -> None:
    """Example installer that needs root (apt). Marked needs_root in the registry.

    Credentials are cached once before the parallel run (see ensure_sudo), so
    sh(..., sudo=True) here runs non-interactively. You may want an
    `apt-get update` first on a stale image.
    """
    report("apt-get install ripgrep")
    sh(["apt-get", "install", "-y", "ripgrep"], report, sudo=True)
    report("done")


def install_mythic_aliases(mythic_dir: Path, report: Callable[[str], None]) -> None:
    add_aliases(
        {
            "mythic-cli": f"sudo {str(mythic_dir / 'mythic-cli')}",
        },
        report,
    )
    report("done -- run `source ~/.bashrc` or open a new shell")


def install_mythic_c2(report: Callable[[str], None]) -> None:
    """
    Install Mythic C2 and if necessary also docker.
    """
    dest = HOME / ".local" / "share" / "MythicC2"
    if dest.exists():
        report("updating repo")
        sh(["git", "-C", str(dest), "pull", "--ff-only"], report)
    else:
        report("cloning its-a-feature/Mythic")
        dest.parent.mkdir(parents=True, exist_ok=True)
        sh(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "https://github.com/its-a-feature/Mythic",
                "--single-branch",
                str(dest),
            ],
            report,
        )

    workdir = dest
    if not (has_docker() and has_compose_plugin()):
        report("need to install docker and docker-compose-plugin")
        distro = detect_distro()
        if "kali" in distro:
            script = workdir / "install_docker_kali.sh"
            sh(["bash", str(script.absolute())], report, sudo=True, cwd=workdir)
        elif "debian" in distro:
            script = workdir / "install_docker_debian.sh"
            sh(["bash", str(script.absolute())], report, sudo=True, cwd=workdir)
        elif "htb" in distro or "ubuntu" in distro or "parrot" in distro:
            script = workdir / "install_docker_ubuntu.sh"
            sh(["bash", str(script.absolute())], report, sudo=True, cwd=workdir)
        else:
            raise ValueError(f"No procedure to install docker for distro {distro}")
        report("docker and docker-compose-plugin installed")

    sh(["systemctl", "start", "docker"], report, sudo=True)
    if not wait_for_docker(timeout=30, report=report, sudo=True):
        raise RuntimeError("docker daemon did not become ready in time")

    sh(["make"], report, sudo=True, cwd=workdir)
    install_mythic_aliases(mythic_dir=workdir, report=report)
    sh(["./mythic-cli"], report, sudo=True, cwd=workdir)
    services = [
        "https://github.com/MythicAgents/apollo",
        "https://github.com/MythicAgents/apfell",
        "https://github.com/MythicAgents/woopsie",
        "https://github.com/MythicAgents/forge",
        "https://github.com/MythicAgents/poseidon",
        "https://github.com/MythicC2Profiles/http",
        "https://github.com/MythicC2Profiles/smb",
    ]
    for service_url in services:
        sh(
            ["./mythic-cli", "install", "github", service_url],
            report,
            sudo=True,
            cwd=workdir,
        )

    mythic_env_file = workdir / ".env"
    config = dotenv_values(str(mythic_env_file.absolute()))
    global important_values_after_install

    important_values_after_install["mythic-user"] = config["MYTHIC_ADMIN_USER"] or "NaN"
    important_values_after_install["mythic-admin"] = (
        config["MYTHIC_ADMIN_PASSWORD"] or "NaN"
    )
    important_values_after_install["mythic-url"] = (
        f"https://127.0.0.1:{config['NGINX_PORT']}"
    )

    report("done")


def install_vimrc(report: Callable[[str], None]) -> None:
    report("writing ~/.vimrc")
    vimrc = HOME / ".vimrc"
    if vimrc.exists():
        shutil.copy2(vimrc, vimrc.with_name(".vimrc.bak"))
    vimrc.write_text(VIMRC_CONTENT)
    report("done")


def install_dummy1(report: Callable[[str], None]) -> None:
    report("Installing Dummy [1]")
    report("done")


def install_dummy2(report: Callable[[str], None]) -> None:
    report("Installing Dummy [2]")
    report("done")


VIMRC_CONTENT = """\
set nocompatible
syntax on
set number relativenumber
set expandtab shiftwidth=4 tabstop=4
set incsearch hlsearch ignorecase smartcase
set clipboard=unnamedplus
set mouse=a
"""


# --------------------------------------------------------------------------- #
# Tool Definitions
# --------------------------------------------------------------------------- #


@dataclass
class Tool:
    name: str
    description: str
    supported_os: list[str]
    install_fn: Callable[[Callable[[str], None]], None]
    default: bool = False
    supported_distros: Optional[list[str]] = None  # None = any distro
    needs_root: bool = False


TOOLS: list[Tool] = [
    Tool("vimrc", "~/.vimrc config", ["linux", "darwin"], install_vimrc, default=False),
    Tool(
        "ripgrep",
        "ripgrep via apt (needs root)",
        ["linux"],
        install_ripgrep,
        default=False,
        supported_distros=["debian", "ubuntu", "kali"],  # e.g. ["kali"] to restrict
        needs_root=True,
    ),
    Tool(
        "mythic-c2",
        "Mythic C2 toolchain via docker-compose",
        ["linux"],
        install_mythic_c2,
        default=False,
        supported_distros=["debian", "ubuntu", "kali"],  # e.g. ["kali"] to restrict
        needs_root=True,
    ),
]


def tools_for_host() -> list[Tool]:
    """Tools available on this host, filtered by OS and by distro."""
    os_name, _ = get_target()
    distro = detect_distro()
    out: list[Tool] = []
    for t in TOOLS:
        if os_name not in t.supported_os:
            continue
        if t.supported_distros is not None and distro not in t.supported_distros:
            continue
        out.append(t)
    return out


# --------------------------------------------------------------------------- #
# Interactive picker (pure Rich). Swap in `questionary.checkbox` here if you
# want a nicer arrow-key UI -- everything else stays the same.
# --------------------------------------------------------------------------- #
def pick_interactive(available: list[Tool]) -> list[Tool]:
    selected = {t.name for t in available if t.default}
    while True:
        table = Table(title="dropkit -- select tools")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("", justify="center")
        table.add_column("Tool", style="bold")
        table.add_column("Description")
        for i, t in enumerate(available, 1):
            mark = "[green]OK[/green]" if t.name in selected else "[dim]--[/dim]"
            root = " [magenta](root)[/magenta]" if t.needs_root else ""
            table.add_row(str(i), mark, t.name, t.description + root)
        console.print(table)
        console.print(
            "[dim]toggle: numbers (e.g. 1 3) | a=all | n=none | enter=confirm[/dim]"
        )
        choice = console.input("> ").strip().lower()
        if choice == "":
            break
        if choice == "a":
            selected = {t.name for t in available}
            continue
        if choice == "n":
            selected = set()
            continue
        for tok in choice.split():
            if tok.isdigit() and 1 <= int(tok) <= len(available):
                selected.symmetric_difference_update({available[int(tok) - 1].name})
    return [t for t in available if t.name in selected]


# --------------------------------------------------------------------------- #
# Sudo pre-authentication -- run ONCE before the parallel pool.
# --------------------------------------------------------------------------- #
def ensure_sudo(chosen: list[Tool]) -> bool:
    """Cache sudo credentials up front so parallel workers don't each prompt.

    Several threads firing a password prompt into the same TTY corrupts input,
    so we authenticate once here with `sudo -v`. Workers then use `sudo -n`
    (see sudo_prefix), which reads the cached timestamp without prompting.
    Returns False if root is required but unavailable.
    """
    if is_root() or not any(t.needs_root for t in chosen):
        return True
    if not shutil.which("sudo"):
        console.print("[red]root required but 'sudo' not found[/red]")
        return False
    console.print("[yellow]some tools need root; caching sudo credentials...[/yellow]")
    try:
        subprocess.run(["sudo", "-v"], check=True)
        return True
    except subprocess.CalledProcessError:
        console.print("[red]sudo authentication failed[/red]")
        return False


# --------------------------------------------------------------------------- #
# Parallel install runner -- ThreadPoolExecutor (installs are I/O bound) with a
# live Rich progress table, one row per tool.
# --------------------------------------------------------------------------- #
def run_installs(tools: list[Tool], jobs: int) -> dict[str, Optional[Exception]]:
    results: dict[str, Optional[Exception]] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.fields[name]:<14}"),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_ids = {
            t.name: progress.add_task("queued", name=t.name, total=1, start=False)
            for t in tools
        }

        def worker(t: Tool) -> None:
            tid = task_ids[t.name]
            progress.start_task(tid)
            t.install_fn(lambda msg: progress.update(tid, description=msg))

        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(worker, t): t for t in tools}
            for fut in as_completed(futs):
                t = futs[fut]
                tid = task_ids[t.name]
                try:
                    fut.result()
                    progress.update(tid, description="[green]done[/green]", completed=1)
                    results[t.name] = None
                except Exception as e:  # noqa: BLE001
                    msg = (
                        e.stderr.strip()
                        if isinstance(e, subprocess.CalledProcessError) and e.stderr
                        else str(e)
                    )
                    progress.update(
                        tid, description=f"[red]FAIL {msg[:60]}[/red]", completed=1
                    )
                    results[t.name] = e
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="Bootstrap a fresh Kali / HTB pwnbox with your tools & configs.",
)


@app.command()
def main(
    tools: Annotated[
        Optional[str], typer.Option("--tools", "-t", help="Comma-separated tool names.")
    ] = None,
    all_: Annotated[
        bool,
        typer.Option("--all", "-a", help="Install everything supported on this host."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip picker; use defaults when no --tools."),
    ] = False,
    jobs: Annotated[
        int, typer.Option("--jobs", "-j", help="Parallel install workers.")
    ] = 4,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--execute",
            help="Dry-run (default): show the plan, install nothing. Pass --execute to install.",
        ),
    ] = True,
    list_: Annotated[
        bool, typer.Option("--list", "-l", help="List available tools and exit.")
    ] = False,
) -> None:
    os_name, arch = get_target()
    distro = detect_distro()
    available = tools_for_host()

    print_banner()

    if list_:
        table = Table(title=f"dropkit tools ({os_name}/{arch}, {distro})")
        table.add_column("Tool", style="bold cyan")
        table.add_column("Default")
        table.add_column("Root")
        table.add_column("Distros")
        table.add_column("Description")
        for t in available:
            table.add_row(
                t.name,
                "yes" if t.default else "no",
                "yes" if t.needs_root else "no",
                "any" if t.supported_distros is None else ",".join(t.supported_distros),
                t.description,
            )
        console.print(table)
        raise typer.Exit()

    if all_:
        chosen = available
    elif tools:
        want = {n.strip() for n in tools.split(",") if n.strip()}
        chosen = [t for t in available if t.name in want]
        missing = want - {t.name for t in chosen}
        if missing:
            console.print(
                f"[yellow]skipping unknown/unsupported:[/yellow] {', '.join(sorted(missing))}"
            )
    elif yes:
        chosen = [t for t in available if t.default]
    else:
        chosen = pick_interactive(available)

    if not chosen:
        console.print("[yellow]nothing selected.[/yellow]")
        raise typer.Exit()

    mode = "[yellow]DRY RUN[/yellow]" if dry_run else "[green]EXECUTE[/green]"
    console.print(
        Panel.fit(
            f"[bold]{os_name}/{arch} ({distro})[/bold]  |  {jobs} workers  |  {mode}\n"
            + "  ".join(f"[cyan]{t.name}[/cyan]" for t in chosen),
            title="dropkit",
            border_style="yellow" if dry_run else "blue",
        )
    )

    console.print("Dropping in cute red pandas ...")

    if dry_run:
        console.print(
            "[yellow]DRY RUN[/yellow] -- no changes will be made. "
            "Pass [bold]--execute[/bold] to install."
        )
        for t in chosen:
            root = " [magenta](root)[/magenta]" if t.needs_root else ""
            console.print(
                f"  would install [cyan]{t.name}[/cyan]{root}  [dim]{t.description}[/dim]"
            )
        raise typer.Exit()

    # Execute path: pre-auth sudo once, then drop root tools if unavailable.
    if not ensure_sudo(chosen):
        skipped = [t.name for t in chosen if t.needs_root]
        chosen = [t for t in chosen if not t.needs_root]
        console.print(f"[yellow]skipping (need root):[/yellow] {', '.join(skipped)}")
        if not chosen:
            console.print("[yellow]nothing left to install.[/yellow]")
            raise typer.Exit(code=1)

    results = run_installs(chosen, jobs=max(1, jobs))

    ok = [n for n, e in results.items() if e is None]
    failed = [n for n, e in results.items() if e is not None]
    console.print()
    console.print(f"[green]installed:[/green] {', '.join(ok) or '-'}")

    global important_values_after_install
    table = Table(title="important variables")
    table.add_column("Key")
    table.add_column("Value")
    for a, b in important_values_after_install.items():
        table.add_row(a, b)

    console.print(table)

    if failed:
        console.print(f"[red]failed:[/red] {', '.join(failed)}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
