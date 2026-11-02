# Ubuntu 24.04 STIG Hardening Runbook

How to use this: work through each finding in order. Run the commands on the target server, then run the verify step. Every finding is tied to the rule title in the OpenSCAP report. This runbook covers Fixes 1 to 16.

Placeholders used below: `<vmid>` is the Proxmox VM ID of the lab VM, `<user>` is the admin account on the lab VM, `<proxmox-host>` and `<lab-vm>` are addresses, and `~/.ssh/<lab-key>` is the SSH key used for the lab.

> **Copying commands:** copy only the commands *between* the ```` ``` ```` lines. Those backtick lines just draw the box in this document. If you paste them into the terminal, the shell swallows everything after them and nothing runs, with no error.

All `oscap` commands are run from inside the SCAP Security Guide folder (`~/scap-security-guide-0.1.82`), because oscap looks for `ssg-ubuntu2404-ds.xml` in the current directory.

---

## Fix 1: DoD notice-and-consent banner for SSH
**Rules:** `banner_etc_issue_net` ("Modify the System Login Banner for Remote Connections") and `sshd_enable_warning_banner_net` ("Enable SSH Warning Banner")

**Why:** The DoD requires users to see a standard banner warning that the system is monitored before they log in. It establishes legal consent to monitoring.

### 1a. Pull the official banner text from the STIG content (never retype it)
```bash
cd ~/scap-security-guide-0.1.82
grep -m1 -o "You are accessing a U.S. Government.*Agreement for details." ssg-ubuntu2404-ds.xml \
  | sed 's/\\n/\n/g' | sudo tee /etc/issue.net
```
- `grep -m1 -o "...start.*end..."` grabs only the first match, and only the matching text.
- `|` passes that output to the next command.
- `sed 's/\\n/\n/g'` turns the literal `\n` sequences from the XML into real line breaks.
- `sudo tee /etc/issue.net` writes the result to the remote-login banner file and also shows it on screen.

### 1b. Tell SSH to show the banner
```bash
echo "Banner /etc/issue.net" | sudo tee /etc/ssh/sshd_config.d/50-stig-banner.conf
sudo sshd -t && sudo systemctl restart ssh
```
- Use a drop-in file in `sshd_config.d/` rather than editing the main config. It keeps the change clean and survives package updates.
- `sshd -t` tests the config syntax before the restart. If the config is broken and you restart anyway, you can lock yourself out of SSH.

### Verify
- Open a **new** SSH session (keep the current one open in case something breaks). The banner should appear before login.
- `sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_banner_etc_issue_net --rule xccdf_org.ssgproject.content_rule_sshd_enable_warning_banner_net ssg-ubuntu2404-ds.xml` should report `pass` for both rules.
- `cat /etc/issue.net` should show each `-` paragraph on its own line. If you see literal `\n` instead, run `sudo sed -i 's/\\n/\n/g' /etc/issue.net` (it swaps each literal backslash-n for a real line break, and `-i` edits the file in place).

---

## Fix 2: SSH login confirmation prompt (rule `banner_etc_profiled_ssh_confirm`)

### The finding
After login, the STIG requires users to actively accept the DoD notice ("Do you agree? [y/N]"). Answering anything but `y` must end the session.

### Why it matters
The pre-login banner only *shows* the notice. The confirmation prompt records that the user actively agreed, which is what makes monitoring consent legally solid.

### Safety first
1. Take a snapshot on the Proxmox host: `qm snapshot <vmid> banner-done`
2. Keep one SSH session open the whole time as a safety net.

### The fix
Do NOT use `oscap xccdf generate fix --rule ...`. This version of oscap ignores `--rule` there and writes the ENTIRE STIG profile (about 30,000 lines). Running that locked me out once. Always run `wc -l` on a generated script before running it.

Instead, scan and fix just this one rule:

```bash
cd ~/scap-security-guide-0.1.82
sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_banner_etc_profiled_ssh_confirm ssg-ubuntu2404-ds.xml
```

- `xccdf eval` checks the rule.
- `--remediate` fixes it if it fails.
- `--rule` limits it to only this rule (unlike `generate fix`, `eval` respects this).
- Expected output: `Result fail`, then `Result fixed`.

It creates `/etc/profile.d/ssh_confirm.sh`, which runs at every login.

### Verify
- `ls -l /etc/profile.d/ssh_confirm.sh` shows that the file exists.
- In a **new** terminal on your own computer, log in. Answer `y` and you get a prompt.
- Log in again and answer `n` (or just press Enter). It should say "Connection closed."
- Rescan: `sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_banner_etc_profiled_ssh_confirm ssg-ubuntu2404-ds.xml` should report `pass`.

---

## Fix 3: Disable Ctrl+Alt+Del reboot (rule `disable_ctrlaltdel_reboot`)

### The finding
On stock Ubuntu, pressing Ctrl+Alt+Del at the console reboots the machine instantly, with no login.

### Why it matters
Anyone at the keyboard (or a bumped key) can take the server down. The STIG requires the key combo to do nothing.

### Safety first
Snapshot from the Proxmox host shell: `qm snapshot <vmid> after-key-cleanup`. This change doesn't touch SSH, so there is no lockout risk.

### Check first
`systemctl status ctrl-alt-del.target`
- It shows `reboot.target`, which means the combo is armed (even though it says "inactive").

### The fix
One command per line:
- `sudo systemctl mask ctrl-alt-del.target`. `mask` points the target at `/dev/null` so it can never fire. Stronger than `disable`.
- `sudo systemctl daemon-reload` tells systemd to reload its settings.

### Verify
- `systemctl status ctrl-alt-del.target` shows `Loaded: masked`.
- Optional rescan: `sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_reboot ssg-ubuntu2404-ds.xml` should report `pass`.

---

## Fix 4: Lock accounts after 3 failed password attempts (rule `accounts_passwords_pam_faillock_deny`)

### The finding
With no lockout, anyone can guess passwords forever. In `/etc/security/faillock.conf`, `deny = 3` was commented out (`#`), so it was off.

### Why it matters
The STIG locks an account after 3 bad passwords, which stops brute-force guessing.

### Safety first
- Snapshot from the Proxmox host shell: `qm snapshot <vmid> before-faillock`
- My SSH login uses a key, not a password, so SSH won't be locked. But 3 wrong `sudo` passwords will lock `sudo`. Keep the Proxmox VM console available as a backup way in.

### Check first
`grep -r deny /etc/security/faillock.conf` shows only `# deny = 3` (commented out).

### The fix
One command per line:
- `cd ~/scap-security-guide-0.1.82`
- `sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny ssg-ubuntu2404-ds.xml`
- Expected: `Result fail`, then `Result fixed`.

### Verify
- `grep -r deny /etc/security/faillock.conf` shows a new line `deny = 3` with no `#`.
- `grep faillock /etc/pam.d/common-auth` shows `pam_faillock.so preauth` (checks for a lock before the password) and `pam_faillock.so authfail` (counts bad passwords).

### If you lock yourself out
From the Proxmox VM console: `sudo faillock --user <user> --reset`

---

## Fix 5: Log out idle sessions after 10 minutes (rule `accounts_tmout`)

### The finding
`echo $TMOUT` printed a blank line, so idle shells never timed out.

### Why it matters
A logged-in window left open on an unattended computer gives anyone a shell. The STIG closes idle sessions after 600 seconds (10 minutes).

### Safety first
Snapshot from the Proxmox host shell: `qm snapshot <vmid> before-tmout`. Low risk: worst case, an idle window closes and you SSH in again.

### The fix
From `~/scap-security-guide-0.1.82`:
- `sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --rule xccdf_org.ssgproject.content_rule_accounts_tmout ssg-ubuntu2404-ds.xml`
- Expected: `Result fail`, then `Result fixed`.

### Verify
- Open a **new** window and SSH in again (old sessions don't pick up login settings).
- `echo $TMOUT` shows `600`.
- Optional: `grep -r TMOUT /etc/profile.d/` shows where it's set.

---

## Fix 6: Install and enable the audit system (rules `package_audit_installed`, `service_auditd_enabled`)

### The finding
`dpkg -l auditd` said "no packages found." There was no audit logging of logins, sudo, or changes.

### Why it matters
auditd is Linux's flight recorder. Many later STIG audit rules depend on it.

### Safety first
Snapshot from the Proxmox host shell: `qm snapshot <vmid> before-auditd`

### The fix
- `sudo apt install auditd -y`

### Verify
From `~/scap-security-guide-0.1.82` (oscap can't find the file from `~`):
- `P=xccdf_org.ssgproject.content_profile_stig` (shortcut so long commands don't break when pasted)
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_package_audit_installed ssg-ubuntu2404-ds.xml` should report `pass`
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_service_auditd_enabled ssg-ubuntu2404-ds.xml` should report `pass` (the "requires rule" warning is OK)

### Tip: finding a rule's real name
Don't guess rule IDs. Search the datastream for them:

`grep -o 'content_rule_[a-z_]*audit[a-z_]*' ssg-ubuntu2404-ds.xml | sort -u`

---

## Fix 7: Lock down the audit rules file (rule `file_permissions_etc_audit_rulesd`)

### The finding
`/etc/audit/rules.d/audit.rules` could be read by more than its owner.

### Why it matters
The audit rules decide what gets logged. If other users can read them, they learn what's being watched and what isn't.

### Safety first
Snapshot from the Proxmox host shell: `qm snapshot <vmid> stigfix`

### The fix
- `sudo chmod 600 /etc/audit/rules.d/audit.rules`
- `600` means the owner (root) can read and write, and nobody else can do anything.
- `640` still FAILS. The rule removes group read too. The right value came from oscap's own fix script for this rule.

### Lesson learned
Never `chmod 777` a security folder to make an error go away. `777` lets everyone read, write, and run it. I put `/etc/audit/rules.d` back with `sudo chmod 750 /etc/audit/rules.d`.

### Verify
From `~/scap-security-guide-0.1.82`:
- `ls -l /etc/audit/rules.d/` shows `-rw-------` on `audit.rules`
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_file_permissions_etc_audit_rulesd ssg-ubuntu2404-ds.xml` should report `pass`

---

## Fix 8: Install the password-quality module (rule `package_pam_pwquality_installed`)

### The finding
`libpam-pwquality` wasn't installed, so nothing enforced password length or complexity.

### Why it matters
This module is what the later password rules (minimum length, character types, dictionary checks) plug into.

### The fix
- `sudo apt install -y libpam-pwquality`

### Verify
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_package_pam_pwquality_installed ssg-ubuntu2404-ds.xml` should report `pass`

---

## Fix 9: Install vlock for locking the console (rule `vlock_installed`)

### The finding
There was no way for a user to lock their terminal session when stepping away.

### Why it matters
The STIG requires users to be able to lock a session on demand, not just wait for the idle timeout from Fix 5.

### The fix
- `sudo apt install -y vlock` (installed vlock 2.2.2-11)
- To use it: type `vlock`, and your password unlocks it.

### Verify
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_vlock_installed ssg-ubuntu2404-ds.xml` should report `pass`

---

## Fix 10: Install smart-card (CAC) support (rule `package_opensc_installed`)

### The finding
The OpenSC smart-card software wasn't installed.

### Why it matters
The STIG expects smart-card (CAC/PIV) login support. OpenSC is the software that talks to the card. I installed the package to satisfy this one rule. The rest of the smart-card rules don't make sense on a home lab, so they stay open (see `results/summary.md`).

### The fix
- Install the OpenSC package with `apt` (check with `dpkg -l | grep opensc`).

### Verify
- `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_package_opensc_installed ssg-ubuntu2404-ds.xml` should report `pass`

---

## Fix 11: Require a password for sudo (rule `sudo_remove_nopasswd`)

### The finding
`/etc/sudoers.d/90-cloud-init-users` had `<user> ALL=(ALL) NOPASSWD:ALL`. Anyone sitting at that user's session could become root with no password. The VM is a cloud-init image, so the account's password was also **locked** (`sudo passwd -S <user>` showed `L`).

### Why it matters
Re-entering your password before root access stops someone who grabs an unlocked session from taking over the system. It's a high-weight rule.

### Safety first
- Snapshot on the Proxmox host first.
- Open a **root safety shell** (`sudo -i`) in a second window and keep it open until the test passes. If sudo breaks, that window can still fix it.

### The fix
One command per line:
1. Give the account a real password first. Otherwise you lock yourself out of sudo:
   - `sudo passwd <user>`
   - `sudo passwd -S <user>` should now show `P` (password set) instead of `L` (locked).
2. Edit the sudoers drop-in safely:
   - `sudo visudo -f /etc/sudoers.d/90-cloud-init-users`
   - `visudo` checks the syntax before saving. A typo in a sudoers file can break sudo for everyone, so never edit it with plain `nano`.
   - Change line 4 from `<user> ALL=(ALL) NOPASSWD:ALL` to `<user> ALL=(ALL) ALL`
   - If visudo prints nothing or says "unchanged," the edit wasn't saved. Run it again.
3. Confirm the file changed:
   - `sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` should return nothing.

### Verify
- In **your own** shell (not the root window), run `sudo -k` (forgets the cached password) and then `sudo whoami`.
- It should ask for the password and then print `root`.
- From `~/scap-security-guide-0.1.82`: `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_sudo_remove_nopasswd ssg-ubuntu2404-ds.xml` should report `pass`
- When it passes, `exit` the root safety shell.

### Gotchas
- Variables like `P` only live in the shell where you set them. After switching between root and your own account, set them again and check with `echo $P`. If `$P` is empty, oscap says "No profile matching suffix '--rule'".
- "Unable to open file: ssg-ubuntu2404-ds.xml" means you're in the wrong folder. `cd ~/scap-security-guide-0.1.82` first.

---

## Fix 12: SSH daemon hardening (7 rules, one drop-in file)

**Rules:** `sshd_set_keepalive`, `sshd_set_idle_timeout`, `sshd_disable_empty_passwords`, `sshd_disable_x11_forwarding`, `sshd_x11_use_localhost`, `sshd_do_not_permit_user_env`, `sshd_enable_pubkey_auth`

### The finding
Seven SSH daemon settings were missing or not at the STIG value. They are all `sshd_config` options, so one drop-in file covers them.

### Why it matters
- `ClientAliveInterval 600` and `ClientAliveCountMax 1` drop an SSH connection that has gone silent for 10 minutes (the server checks every 600 seconds and gives up after one missed check).
- `PermitEmptyPasswords no` blocks logins on accounts with no password.
- `X11Forwarding no` and `X11UseLocalhost yes` turn off graphical forwarding, which is extra attack surface on a server. If it were ever enabled, the second setting keeps it off the network.
- `PermitUserEnvironment no` stops users from setting environment variables that change how sshd behaves.
- `PubkeyAuthentication yes` keeps key-based login on, which is how I log in.

### Safety first
- Snapshot from the Proxmox host shell: `qm snapshot <vmid> prefix12`. This one snapshot is the rollback point for Fixes 12 to 16.
- Keep one SSH session open the whole time. Test with a **second** session before you close the first.

### The fix
```bash
sudo tee /etc/ssh/sshd_config.d/10-stig.conf >/dev/null <<'EOF'
ClientAliveInterval 600
ClientAliveCountMax 1
PermitEmptyPasswords no
X11Forwarding no
X11UseLocalhost yes
PermitUserEnvironment no
PubkeyAuthentication yes
EOF
sudo sshd -t && echo OK
sudo systemctl restart ssh
```
- A drop-in in `sshd_config.d/` keeps the change separate from the main config, same as the banner in Fix 1.
- `sshd -t` checks the syntax first. Only restart if it prints `OK`.

### Verify
- Open a **new** SSH session while the old one is still open. It should connect normally.
- `sudo sshd -T | grep -Ei 'clientalive|permitempty|x11|permituserenv|pubkeyauth'` shows the effective values.
- Rescan one rule, for example: `sudo oscap xccdf eval --profile $P --rule xccdf_org.ssgproject.content_rule_sshd_set_keepalive ssg-ubuntu2404-ds.xml` should report `pass`.

---

## Fix 13: Kernel settings and USB storage (4 rules)

**Rules:** `sysctl_net_ipv4_tcp_syncookies`, `sysctl_kernel_dmesg_restrict`, `sysctl_kernel_randomize_va_space`, `kernel_module_usb-storage_disabled`

### The finding
Three kernel settings were not at the STIG value, and the USB storage driver could be loaded.

### Why it matters
- `net.ipv4.tcp_syncookies = 1` helps the server survive SYN flood attacks.
- `kernel.dmesg_restrict = 1` keeps non-root users from reading kernel messages, which can leak memory addresses.
- `kernel.randomize_va_space = 2` turns on full address space randomization (ASLR), which makes memory exploits harder.
- Blocking the `usb-storage` driver means nobody can plug in a USB drive to copy data on or off the machine.

### Safety first
Covered by the `prefix12` snapshot from Fix 12. These changes don't touch SSH, so there is no lockout risk.

### The fix
```bash
sudo tee /etc/sysctl.d/99-stig.conf >/dev/null <<'EOF'
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
EOF
sudo sysctl --system | tail -5
```
- `sysctl --system` loads every file in `/etc/sysctl.d/` right now. The last lines of the output list the three values I set.

```bash
echo -e "install usb-storage /bin/false\nblacklist usb-storage" | sudo tee /etc/modprobe.d/usb-storage.conf
```
- `install usb-storage /bin/false` makes any attempt to load the module run `false` instead.
- `blacklist usb-storage` stops it from loading automatically.

### Verify
- `sysctl net.ipv4.tcp_syncookies kernel.dmesg_restrict kernel.randomize_va_space` prints `1`, `1`, `2`.
- `cat /etc/modprobe.d/usb-storage.conf` shows both lines.
- Rescan the rules with `--rule`, the same way as in Fix 12.

---

## Fix 14: Firewall (2 rules)

**Rules:** `check_ufw_active`, `ufw_rate_limit`

### The finding
The ufw firewall was installed but not active, and there was no rate limit on SSH.

### Why it matters
A host firewall that denies incoming traffic by default means only the ports I choose are reachable. The rate limit slows down password-guessing against SSH.

### Safety first
- **Allow SSH before you enable the firewall.** In Step 6 of the lab notes, the full STIG profile enabled ufw with no SSH rule and locked me out. Here the allow rule goes in first, in the same command sequence.
- Covered by the `prefix12` snapshot. Keep your current SSH session open and test with a second one.

### The fix
```bash
sudo apt install -y ufw
sudo ufw limit 22/tcp
sudo ufw --force enable
sudo ufw status verbose
```
- ufw was already installed, so `apt` changed nothing.
- `ufw limit 22/tcp` allows SSH and blocks an address that makes 6 or more connection attempts in 30 seconds. One rule covers `ufw_rate_limit`.
- `--force` skips the "this may disrupt SSH connections" prompt. That is safe only because the SSH rule already exists.

### Verify
`ufw status verbose` shows:
- `Status: active`
- `Default: deny (incoming), allow (outgoing), disabled (routed)`
- `22/tcp LIMIT IN` for both IPv4 and IPv6
- Open a **new** SSH session to confirm you can still get in.

---

## Fix 15: Time sync with chrony (2 rules)

**Rules:** `package_chrony_installed`, `package_timesyncd_removed`

### The finding
The VM used the default `systemd-timesyncd`. The STIG wants chrony and no timesyncd.

### Why it matters
Accurate, consistent time matters for audit logs, log correlation and certificate checks. The STIG standardizes on chrony.

### Safety first
Covered by the `prefix12` snapshot. No SSH impact.

### The fix
```bash
sudo apt install -y chrony
sudo apt purge -y systemd-timesyncd 2>/dev/null
systemctl is-active chrony
chronyc tracking | head -3
```
- Installing chrony removed `systemd-timesyncd` on its own. The `purge` line also deletes its leftover config files.
- Expected: `active`.

### Verify
- Right after the install, `chronyc tracking` showed `Stratum 0` and a 1970 reference time. That means chrony had not synced yet. I haven't rechecked whether it syncs on this lab network. The two rules only check that the packages are in the right state.
- Rescan both rules with `--rule`.

---

## Fix 16: Log and journal permissions (3 rules)

**Rules:** `dir_permissions_system_journal`, `file_permissions_journalctl`, `file_permissions_var_log_stig`

### The finding
The journal directory, the `journalctl` binary and some files under `/var/log` could be read or changed by more users than the STIG allows.

### Why it matters
Logs show who did what on the system. If ordinary users can read or edit them, an attacker can learn from them or tamper with the evidence.

### Safety first
Covered by the `prefix12` snapshot. Permission changes on logs don't affect SSH.

### The fix
```bash
sudo chmod 2750 /var/log/journal 2>/dev/null; sudo chmod 2750 /run/log/journal 2>/dev/null
sudo chmod 740 /usr/bin/journalctl
sudo find /var/log -type f -perm /137 ! -name 'wtmp' ! -name 'btmp' ! -name 'lastlog' -exec chmod 640 {} +
ls -ld /var/log/journal /usr/bin/journalctl
```
- `2750` on the journal directories: owner full access, group read and enter, nobody else. The leading `2` keeps new files in the same group.
- `740` on `journalctl`: only root can run it.
- The `find` line sets `640` on any log file that is more open than that. `-perm /137` matches a file if any of the bits in `137` are set. I skip `wtmp`, `btmp` and `lastlog` because other tools expect them to be group-readable.

### Verify
- `ls -ld` shows `drwxr-s---` on the journal directory and `-rwxr-----` on `journalctl`.
- The `+` at the end of the journal directory's permissions means it has an extra access list. That is normal.
- Rescan the three rules with `--rule`.

---

## Rescan after Fix 16: 68.60%

A full rescan after Fix 16 scored **68.596458**, reported as 68.60%. The report is `~/report-fix16.html` on the VM. I did not record per-rule pass and fail counts for this scan.

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ~/results-fix16.xml --report ~/report-fix16.html ~/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml > /dev/null
grep -o 'urn:xccdf:scoring:default"[^>]*>[0-9.]*' ~/results-fix16.xml
```

### Lesson learned
My first scan command used `/usr/share/xml/scap/ssg/content/` for the content file and sent all output to `/dev/null` with `2>&1`. It failed without writing a results file, and the only sign was a "No such file" error from the `grep` afterwards. The content file is at `~/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml`. Don't hide stderr on a scan. Hide only stdout, so a bad path shows up right away. `find / -name 'ssg-ubuntu2404-ds.xml'` locates the file.

---

## Score history (weighted)

| After | oscap score |
|---|---|
| Baseline | 51.38% |
| Fix 6 | 60.03% |
| Fix 10 | 61.22% |
| Fix 11 | 62.02% |
| Fix 16 | 68.60% |

Package-install rules are low weight, so the score moves slowly. Fixes 12 to 16 (SSH settings, kernel settings, firewall, time sync, log permissions) added about 6.6 points in one session. The bigger remaining gains are in the password, faillock, and AIDE rules.

Full rescan command (from `~/scap-security-guide-0.1.82`):
- `sudo oscap xccdf eval --profile $P --results ~/results-fixN.xml --report ~/report-fixN.html ssg-ubuntu2404-ds.xml`
- Score: `grep -o 'urn:xccdf:scoring:default"[^>]*>[0-9.]*' ~/results-fixN.xml`
- The VM has no browser. Copy the report to your workstation to read it. Don't install `xdg-utils` on the VM, since it pulls in about 97 graphics packages that are extra attack surface.

---

## Appendix: connecting from a new computer

The lab VM sits on an isolated bridge behind the Proxmox host, so SSH goes through the host as a jump box.

1. Make a key: `ssh-keygen -t ed25519 -f ~/.ssh/<lab-key> -C "<comment>"`
2. Add the **public** key (`~/.ssh/<lab-key>.pub`) to `authorized_keys` on the Proxmox host AND `~/.ssh/authorized_keys` on the lab VM. Never share the file without `.pub`.
3. In each new terminal, load the key into the SSH agent, one command per line:
   - `eval "$(ssh-agent -s)"`
   - `ssh-add ~/.ssh/<lab-key>`
4. Connect: `ssh -J <user>@<proxmox-host> <user>@<lab-vm>`
   - Why the agent? `-i` only gives the key to the LAST stop (the VM). The jump through Proxmox needs it too. The agent offers it at every stop.
- Always check the shell prompt before typing, so you know whether you are on your own computer, the Proxmox host, or the lab VM.

## Connect to the lab VM

To avoid typing the jump command each time, add a host alias to `~/.ssh/config` on your workstation:

    Host lab
        HostName <lab-vm>
        User <user>
        ProxyJump <user>@<proxmox-host>
        IdentityFile ~/.ssh/<lab-key>

Then connect with:

    ssh lab

Type `y` at the USG consent prompt to get in.
