#!/usr/bin/env python3
"""htb -- seamless VPN + target management for HackTheBox labs on Parrot/Kali.

Typer + Rich CLI, same house style as dropkit. Manages OpenVPN tunnels through
systemd (auto-reconnect + logging for free) and sets up per-box working state.

    htb up [profile]        bring a lab VPN up (stops any other HTB tunnel first)
    htb down                tear the current tunnel down
    htb switch <profile>    down + up in one step
    htb status              show tunnel state, profile and tun IP
    htb lhost               print the current tun IP (for $(lhost) in payloads)
    htb list                list available profiles
    htb target <ip> <name>  add <name>.htb to /etc/hosts, make a workdir
    htb untarget <name>     remove that hosts entry again

--------------------------------------------------------------------------- #
PROFILES
--------------------------------------------------------------------------- #
Drop your HackTheBox .ovpn files here:

    ~/htb-vpns/*.ovpn

The *stem* of the filename is the profile name, e.g.

    ~/htb-vpns/lab_free.ovpn     -> `htb up lab_free`
    ~/htb-vpns/release.ovpn      -> `htb up release`

On `up`, the chosen profile is copied (as root, mode 600) to
/etc/openvpn/client/htb-<profile>.conf and started as the systemd unit
openvpn-client@htb-<profile>.service. HackTheBox only permits one VPN
connection per user, so `up`/`switch` stop every other htb-* tunnel first.

--------------------------------------------------------------------------- #
REQUIREMENTS
--------------------------------------------------------------------------- #
  * openvpn package (provides the openvpn-client@.service systemd template)
  * sudo (root is needed for systemctl, copying the config, editing /etc/hosts)

If a profile uses `auth-user-pass` with no credentials file, systemd cannot
prompt for a password; the script warns about this. Point it at a 0600 file
(`auth-user-pass /etc/openvpn/client/htb.auth`) if your profile needs creds.

--------------------------------------------------------------------------- #
SPLIT TUNNELING (`--split`)
--------------------------------------------------------------------------- #
HTB .ovpn profiles pull in `redirect-gateway`, which routes ALL of the VM's
traffic through the tunnel. In a dedicated lab VM that's usually fine. If you'd
rather keep normal browsing off the VPN and only send lab traffic through it,
use:

    htb up <profile> --split
    htb switch <profile> --split

In split mode the installed config has any local `redirect-gateway` lines
commented out and gains `pull-filter ignore "redirect-gateway"`, so a
server-pushed redirect is dropped too. The server's pushed lab-subnet routes
(the 10.10.x.x networks) still get installed, so the boxes remain reachable
while your default route stays on your normal interface. The flag only affects
the copy under /etc/openvpn/client -- your ~/htb-vpns source file is untouched.
Because the config is rewritten on every `up`, dropping `--split` on the next
connect returns you to full-tunnel.

--------------------------------------------------------------------------- #
SHELL INTEGRATION (important)
--------------------------------------------------------------------------- #
`up`/`switch`/`target` want to change your CURRENT shell -- export LHOST (your
tun IP, for reverse shells) and TARGET, and cd into the box workdir. A child
process can't do that, so those commands, when run with --emit-env, print the
shell lines to stdout while all human output goes to stderr. The `htb` shell
function in htb.sh evals only that stdout. Source htb.sh from your rc file and
always drive this through the `htb` function, not `python3 htb.py` directly.

--------------------------------------------------------------------------- #
RECONNECTS / CHANGING IPs
--------------------------------------------------------------------------- #
Two IPs drift during an engagement:

  * The TARGET box IP, after a release/re-spawn. Just re-run
    `htb target <newip> <name>` -- the hosts entry for that name (or IP) is
    replaced, no stale duplicate.

  * YOUR tun IP (LHOST), after the VPN reconnects and OpenVPN hands you a new
    address. The LHOST exported at connect time is a snapshot and goes stale.
    `htb lhost` always does a LIVE lookup of the current tun IP, so use
    `$(lhost)` (the shell helper in htb.sh) in payloads/listeners instead of
    the static $LHOST and you never call back to a dead address.
"""

# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "typer>=0.12.0",
#     "rich>=13.0.0",
# ]
# ///

from __future__ import annotations

import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
HOME = Path.home()
VPN_DIR = HOME / "htb-vpns"               # where your *.ovpn profiles live
HTB_ROOT = HOME / "htb"                   # per-box working directories
CLIENT_DIR = Path("/etc/openvpn/client")  # systemd openvpn-client@ config dir
SERVICE_PREFIX = "htb-"                   # instance name prefix -> htb-<profile>

HOSTS = Path("/etc/hosts")
HOSTS_START = "# >>> htb targets >>>"
HOSTS_END = "# <<< htb targets <<<"

SPLIT_MARKER = "# htb --split: default-route redirect disabled"

# Two consoles: human output normally goes to stdout, but in --emit-env mode it
# must move to stderr so only the shell lines land on stdout. UI points at
# whichever is active (see _set_emit).
console = Console()
console_err = Console(stderr=True)
UI = console
EMIT = False


def _set_emit(flag: bool) -> None:
    global EMIT, UI
    EMIT = flag
    UI = console_err if flag else console


def emit(line: str) -> None:
    """Write a shell command to real stdout for the `htb` function to eval."""
    sys.stdout.write(line + "\n")


# --------------------------------------------------------------------------- #
# Shell / root helpers (same pattern as dropkit)
# --------------------------------------------------------------------------- #
def is_root() -> bool:
    return getattr(os, "geteuid", lambda: 1)() == 0


def sudo_prefix() -> list[str]:
    if is_root():
        return []
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    raise RuntimeError("root required but 'sudo' not available")


def run(
    cmd: list[str], sudo: bool = False, check: bool = True
) -> subprocess.CompletedProcess:
    full = sudo_prefix() + cmd if sudo else cmd
    try:
        return subprocess.run(full, check=check, capture_output=True, text=True)
    except FileNotFoundError:
        # Binary not on PATH (e.g. ip/systemctl missing). When the caller asked
        # to check, let it surface; otherwise degrade to an empty result so the
        # state-reading helpers just report "down / no interface".
        if check:
            raise
        return subprocess.CompletedProcess(full, returncode=127, stdout="", stderr="")


def ensure_sudo() -> None:
    """Cache sudo credentials once, up front, with an interactive `sudo -v`.

    Works from inside $(...) command substitution because sudo reads the
    password from the controlling tty, not stdin/stdout.
    """
    if is_root():
        return
    if not shutil.which("sudo"):
        UI.print("[red]root required but 'sudo' not found[/red]")
        raise typer.Exit(1)
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        UI.print("[red]sudo authentication failed[/red]")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #
def list_profiles() -> list[str]:
    if not VPN_DIR.exists():
        return []
    return sorted(p.stem for p in VPN_DIR.glob("*.ovpn"))


def resolve_profile(name: Optional[str]) -> str:
    profs = list_profiles()
    if name:
        name = name[:-5] if name.endswith(".ovpn") else name
        if name not in profs:
            UI.print(f"[red]no profile '{name}'[/red] in {VPN_DIR}")
            if profs:
                UI.print("available: " + ", ".join(profs))
            raise typer.Exit(1)
        return name
    if len(profs) == 1:
        return profs[0]
    if not profs:
        UI.print(f"[red]no .ovpn profiles found in {VPN_DIR}[/red]")
    else:
        UI.print("[yellow]multiple profiles; specify one:[/yellow] " + ", ".join(profs))
    raise typer.Exit(1)


def _apply_split(content: str) -> str:
    """Rewrite a profile for split tunnelling.

    Comments out any local `redirect-gateway` directives and appends a
    `pull-filter ignore "redirect-gateway"` so a server-pushed redirect is
    dropped as well. Pushed lab-subnet routes are left intact, so the boxes stay
    reachable while the default route stays on the normal interface.
    """
    out = []
    for line in content.splitlines():
        if line.strip().startswith("redirect-gateway"):
            out.append(f"# {line}  {SPLIT_MARKER}")
        else:
            out.append(line)
    out += ["", SPLIT_MARKER, 'pull-filter ignore "redirect-gateway"']
    return "\n".join(out) + "\n"


def install_profile(prof: str, split: bool = False) -> str:
    """Copy the profile into CLIENT_DIR (root, 0600) and return its unit name.

    Rewritten and copied every time -- it's cheap, keeps /etc in sync if you
    re-download a profile, and means dropping `--split` reverts to full-tunnel
    on the next connect. `install -D` creates CLIENT_DIR if missing. The source
    file in ~/htb-vpns is never modified.
    """
    src = VPN_DIR / f"{prof}.ovpn"
    content = src.read_text(errors="ignore")

    for line in content.splitlines():
        if line.strip() == "auth-user-pass":
            UI.print(
                "[yellow]profile uses 'auth-user-pass' with no file; systemd "
                "can't prompt. Add a 0600 creds file if the connect hangs.[/yellow]"
            )
            break

    if split:
        content = _apply_split(content)

    inst = f"{SERVICE_PREFIX}{prof}"
    dst = CLIENT_DIR / f"{inst}.conf"
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(content)
        tmp = tf.name
    try:
        run(["install", "-D", "-m", "600", tmp, str(dst)], sudo=True)
    finally:
        os.unlink(tmp)
    return f"openvpn-client@{inst}.service"


# --------------------------------------------------------------------------- #
# Tunnel state
# --------------------------------------------------------------------------- #
def active_units() -> list[str]:
    """Active openvpn-client@htb-* systemd units."""
    r = run(
        [
            "systemctl",
            "list-units",
            "openvpn-client@*.service",
            "--state=active",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        check=False,
    )
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[0].startswith(f"openvpn-client@{SERVICE_PREFIX}"):
            out.append(parts[0])
    return out


def unit_profile(unit: str) -> str:
    """openvpn-client@htb-release.service -> release"""
    inst = unit.split("@", 1)[-1].rsplit(".service", 1)[0]
    return inst[len(SERVICE_PREFIX):] if inst.startswith(SERVICE_PREFIX) else inst


def tun_iface() -> Optional[str]:
    r = run(["ip", "-o", "link", "show"], check=False)
    for line in r.stdout.splitlines():
        seg = line.split(":")
        if len(seg) >= 2:
            name = seg[1].strip().split("@")[0]
            if name.startswith("tun"):
                return name
    return None


def iface_ip(iface: str) -> Optional[str]:
    r = run(["ip", "-4", "-o", "addr", "show", "dev", iface], check=False)
    toks = r.stdout.split()
    if "inet" in toks:
        return toks[toks.index("inet") + 1].split("/")[0]
    return None


def wait_for_tun(timeout: float) -> Optional[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        iface = tun_iface()
        if iface:
            ip = iface_ip(iface)
            if ip:
                return ip
        time.sleep(1.0)
    return None


# --------------------------------------------------------------------------- #
# /etc/hosts management (managed block, like dropkit's alias block)
# --------------------------------------------------------------------------- #
def _hosts_block_lines(text: str) -> list[str]:
    if HOSTS_START in text and HOSTS_END in text:
        s = text.index(HOSTS_START) + len(HOSTS_START)
        e = text.index(HOSTS_END)
        return [l for l in text[s:e].splitlines() if l.strip()]
    return []


def _write_hosts(content: str) -> None:
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(content)
        tmp = tf.name
    try:
        run(["cp", tmp, str(HOSTS)], sudo=True)
    finally:
        os.unlink(tmp)


def set_target_host(ip: str, name: str) -> None:
    text = HOSTS.read_text()
    host = f"{name}.htb"
    lines = _hosts_block_lines(text)
    # drop any existing entry for this hostname or IP, then add the fresh one
    lines = [l for l in lines if host not in l.split() and l.split()[0] != ip]
    lines.append(f"{ip}\t{host} {name}")
    block = HOSTS_START + "\n" + "\n".join(lines) + "\n" + HOSTS_END
    if HOSTS_START in text and HOSTS_END in text:
        s = text.index(HOSTS_START)
        e = text.index(HOSTS_END) + len(HOSTS_END)
        new = text[:s] + block + text[e:]
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"
    _write_hosts(new)


def clear_target_host(name: str) -> bool:
    text = HOSTS.read_text()
    host = f"{name}.htb"
    lines = _hosts_block_lines(text)
    kept = [l for l in lines if host not in l.split()]
    if len(kept) == len(lines):
        return False
    if HOSTS_START in text and HOSTS_END in text:
        s = text.index(HOSTS_START)
        e = text.index(HOSTS_END) + len(HOSTS_END)
        block = (
            HOSTS_START + "\n" + "\n".join(kept) + "\n" + HOSTS_END if kept
            else ""
        )
        new = text[:s] + block + text[e:]
        # collapse the blank line we may have left behind
        new = new.replace("\n\n\n", "\n\n")
        _write_hosts(new)
    return True


def make_box_dirs(name: str) -> Path:
    base = HTB_ROOT / name
    for sub in ("nmap", "loot", "notes"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


# --------------------------------------------------------------------------- #
# Core operations
# --------------------------------------------------------------------------- #
def _down(quiet: bool = False) -> None:
    ensure_sudo()
    units = active_units()
    if not units:
        if not quiet:
            UI.print("no active HTB tunnel")
        return
    for u in units:
        run(["systemctl", "stop", u], sudo=True, check=False)
        UI.print(f"stopped {u}")


def _up(profile: Optional[str], timeout: float, split: bool = False) -> None:
    prof = resolve_profile(profile)
    ensure_sudo()
    unit = install_profile(prof, split=split)
    if split:
        UI.print("[dim]split tunnel: default route stays off the VPN[/dim]")

    for u in active_units():
        if u != unit:
            run(["systemctl", "stop", u], sudo=True, check=False)
            UI.print(f"stopped {u} (one connection per user)")

    UI.print(f"starting [cyan]{prof}[/cyan] ...")
    run(["systemctl", "start", unit], sudo=True, check=False)

    ip = wait_for_tun(timeout)
    if not ip:
        UI.print(f"[red]tunnel did not come up within {timeout:.0f}s[/red]")
        jr = run(["journalctl", "-u", unit, "-n", "15", "--no-pager"],
                 sudo=True, check=False)
        if jr.stdout.strip():
            UI.print(f"[dim]{jr.stdout.strip()}[/dim]")
        raise typer.Exit(1)

    UI.print(f"[green]connected[/green] {prof} -> [bold]{ip}[/bold]")
    if EMIT:
        emit(f"export LHOST={ip}")


def _target(ip: str, name: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        UI.print(f"[red]invalid IP:[/red] {ip}")
        raise typer.Exit(1)
    ensure_sudo()
    set_target_host(ip, name)
    base = make_box_dirs(name)
    UI.print(f"[green]target set[/green] {name}.htb -> [bold]{ip}[/bold]")
    UI.print(f"workdir {base}")
    if EMIT:
        emit(f"export TARGET={ip}")
        emit(f"cd {shlex.quote(str(base))}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="Seamless HackTheBox VPN + target management.",
)


@app.command(help="Bring a lab VPN up (stops any other HTB tunnel first).")
def up(
    profile: Optional[str] = typer.Argument(None, help="Profile name (stem of the .ovpn)."),
    timeout: float = typer.Option(25.0, "--timeout", help="Seconds to wait for tun IP."),
    split: bool = typer.Option(
        False, "--split", help="Split tunnel: route only lab subnets, not all traffic."
    ),
    emit_env: bool = typer.Option(False, "--emit-env", hidden=True),
) -> None:
    _set_emit(emit_env)
    _up(profile, timeout, split=split)


@app.command(help="Tear the current tunnel down.")
def down() -> None:
    _down()


@app.command(help="Switch to another profile (down + up).")
def switch(
    profile: str = typer.Argument(..., help="Profile to switch to."),
    timeout: float = typer.Option(25.0, "--timeout"),
    split: bool = typer.Option(
        False, "--split", help="Split tunnel: route only lab subnets, not all traffic."
    ),
    emit_env: bool = typer.Option(False, "--emit-env", hidden=True),
) -> None:
    _set_emit(emit_env)
    _down(quiet=True)
    _up(profile, timeout, split=split)


@app.command(help="Show tunnel state, profile and tun IP.")
def status() -> None:
    units = active_units()
    iface = tun_iface()
    ip = iface_ip(iface) if iface else None
    table = Table(title="htb status")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    table.add_row("tunnel", "[green]up[/green]" if units else "[red]down[/red]")
    table.add_row("profile", ", ".join(unit_profile(u) for u in units) or "-")
    table.add_row("iface", iface or "-")
    table.add_row("LHOST", ip or "-")
    UI.print(table)


@app.command(help="Print the current tun IP (live), for $(lhost) in payloads.")
def lhost() -> None:
    # Bare value to stdout so it's cleanly capturable in $(...). No tunnel ->
    # exit 1 with empty output, so $(lhost) expands to nothing.
    iface = tun_iface()
    ip = iface_ip(iface) if iface else None
    if not ip:
        raise typer.Exit(1)
    sys.stdout.write(ip + "\n")


@app.command(name="list", help="List available profiles.")
def list_() -> None:
    profs = list_profiles()
    if not profs:
        UI.print(f"[yellow]no .ovpn profiles in {VPN_DIR}[/yellow]")
        return
    table = Table(title=f"profiles in {VPN_DIR}")
    table.add_column("Profile", style="bold cyan")
    for p in profs:
        table.add_row(p)
    UI.print(table)


@app.command(help="Add <name>.htb to /etc/hosts and make a workdir.")
def target(
    ip: str = typer.Argument(..., help="Box IP, e.g. 10.10.11.42"),
    name: str = typer.Argument(..., help="Short box name, e.g. keeper"),
    emit_env: bool = typer.Option(False, "--emit-env", hidden=True),
) -> None:
    _set_emit(emit_env)
    _target(ip, name)


@app.command(help="Remove a target's /etc/hosts entry (workdir is kept).")
def untarget(
    name: str = typer.Argument(..., help="Box name to remove."),
) -> None:
    ensure_sudo()
    if clear_target_host(name):
        UI.print(f"[green]removed[/green] {name}.htb")
    else:
        UI.print(f"no hosts entry for {name}.htb")


if __name__ == "__main__":
    app()
