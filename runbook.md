# Ubuntu 24.04 STIG Hardening Runbook

How to use this: work through each finding in order. Run the commands on the target server, then run the verify step. Every finding is tied to the rule title in the OpenSCAP report. This runbook covers Fixes 1 to 28.

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

## Fix 17: Audit rules for ssh-agent and ssh-keysign (2 rules)

**Rules:** the two audit rules that watch execution of `ssh-agent` and `ssh-keysign`

### The finding
Nothing recorded it when a user ran `ssh-agent` or `ssh-keysign`. Both handle SSH keys, so the STIG wants every use logged.

### Why it matters
If someone uses a key-handling tool, the audit log should show who and when.

### Safety first
Audit rules only add logging, so there is no lockout risk. Take a snapshot anyway: `qm snapshot <vmid> before-audit-rules`.

### The fix
```bash
sudo tee /etc/audit/rules.d/stig-ssh.rules >/dev/null <<'EOF2'
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh
EOF2
sudo chmod 0600 /etc/audit/rules.d/stig-ssh.rules
sudo augenrules --load
sudo auditctl -l | grep -E 'ssh-agent|ssh-keysign'
```
- `-F perm=x` logs execution. `-F auid>=1000 -F auid!=unset` means "real logged-in users, not system services."
- `-k privileged-ssh` is a label I chose so I can search the log later.
- `augenrules --load` merges every file in `/etc/audit/rules.d/` and loads the result.

### Verify
- `sudo auditctl -l` lists both rules.
- `sudo ls -l /etc/audit/rules.d/` shows `-rw-------` on the new file.

### Lesson learned: the file must be `0600`, not `0640`
My first attempt left the new file at `0640`. The earlier rule `file_permissions_etc_audit_rulesd` (Fix 7) checks **every** file in that folder, so `0640` made that rule fail again. Run `chmod 0600` on every new file in `/etc/audit/rules.d/`.

---

## Fix 18: SSH root login and approved encryption lists

**Rules:** `sshd_disable_root_login` and the three "approved ciphers, MACs and key exchange, in order" rules (`sshd_use_approved_ciphers_ordered_stig`, `sshd_use_approved_macs_ordered_stig`, `sshd_use_approved_kex_ordered_stig`)

### The finding
These rules still failed after Fix 12, even though the SSH daemon already used strong settings.

### Why it matters
The STIG allows only a short list of encryption methods. It also requires `PermitRootLogin no`, so nobody can log in directly as root over SSH.

### The fix
Add `PermitRootLogin no` and the three lists to the same drop-in file as Fix 12, `/etc/ssh/sshd_config.d/10-stig.conf`. Use the **exact lines from the STIG fix script** for those rules. Do not copy the description text on the report: the scanner compares the setting against one exact ordered list, so the same methods in a different order, or text copied from the description, still fail.

```bash
sudo sshd -t && echo OK
sudo systemctl restart ssh
```
- Keep one SSH session open and test with a second one before closing the first.

### Verify
- `sudo sshd -T | grep -Ei '^(permitrootlogin|ciphers|macs|kexalgorithms)'` shows `permitrootlogin no` and the three lists.
- After the rescan, every SSH-related rule passed.

---

## Fix 19: Audit rules for privileged commands (19 rules)

**Rules:** the audit rules for running `apparmor_parser`, `chage`, `chfn`, `chsh`, `crontab`, `gpasswd`, `kmod`, `mount`, `newgrp`, `pam_timestamp_check`, `passwd`, `su`, `sudo`, `sudoedit`, `umount`, `unix_update` and `usermod`, plus the `fdisk` and `modprobe` watches

### The finding
None of these commands were logged. They change accounts, passwords, mounts and kernel modules.

### Why it matters
These are the tools an attacker (or a mistake) would use to gain or change access. The log should show who ran them.

### The fix
Write one rule per command in `/etc/audit/rules.d/stig-privileged.rules`. Each of the 17 execution rules has the same shape, so look up the real path first:

```bash
command -v apparmor_parser chage chfn chsh crontab gpasswd kmod mount newgrp pam_timestamp_check passwd su sudo sudoedit umount unix_update usermod
```
- On Ubuntu 24.04, `/sbin` and `/bin` are links to `/usr/sbin` and `/usr/bin`. Use the path `command -v` prints for your system.

One line per command, with the real path in place of the example:
```
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
```
The two extra rules are watches on a program file:
```
-w /sbin/fdisk -p x -k fdisk
-w /sbin/modprobe -p x -k modules
```

```bash
sudo chmod 0600 /etc/audit/rules.d/stig-privileged.rules
sudo augenrules --load
sudo auditctl -l | wc -l
```

### Verify
- `sudo auditctl -l | wc -l` goes up by the number of rules you added.
- `sudo auditctl -l | grep -c privileged` shows 17 lines for this file's execution rules.

---

## Fix 20: Audit watches on account, log and cron files (15 rules)

### The finding
Changes to account files, login records and cron folders were not logged.

### Why it matters
A new user, a changed password, a new sudo rule, a cleared login record or a new scheduled job are all classic signs of someone taking over a system.

### The fix
`-w <path> -p wa` means "log any write or attribute change to this path." Put these in `/etc/audit/rules.d/stig-watches.rules`, each followed by a label (`-k`) of your choice:

- `/etc/group`, `/etc/gshadow`, `/etc/security/opasswd`, `/etc/passwd`, `/etc/shadow`
- `/etc/sudoers`, `/etc/sudoers.d/`
- `/var/log/faillog`, `/var/log/lastlog`, `/var/log/btmp`, `/var/run/utmp`, `/var/log/wtmp`
- `/etc/cron.d/`, `/var/spool/cron`, `/var/log/journal/`

Example line:
```
-w /etc/shadow -p wa -k usergroup_modification
```

```bash
sudo chmod 0600 /etc/audit/rules.d/stig-watches.rules
sudo augenrules --load
sudo auditctl -l | grep -c -- '-p wa'
```

### Verify
- The last command prints 15 for this file's watches (plus any `-p wa` rules you already had).

---

## Fix 21: Audit rules for system calls (permissions, deletes, failed access, modules, privilege)

### The finding
The STIG wants the kernel's own actions logged, not just file paths. These are "system calls": the requests a program makes to the kernel.

### Why it matters
Changing file permissions or owners, deleting files, being refused access to a file, loading kernel modules and running programs with someone else's privileges are all things an investigator needs to see.

### The fix
Put these rules in `/etc/audit/rules.d/stig-syscalls.rules`. Each group needs one line for 64-bit programs (`-F arch=b64`) and one for 32-bit programs (`-F arch=b32`):

- permission and ownership changes (`chmod`, `chown` and their variants)
- extended attribute changes (`setxattr` and its variants)
- deletes and renames (`unlink`, `rename` and their variants)
- failed file access (`open`, `creat`, `truncate` and their variants with `-F exit=-EACCES` or `-F exit=-EPERM`)
- kernel module loading and unloading (`init_module`, `finit_module`, `delete_module`)
- the `chacl`, `setfacl` and `chcon` programs
- programs that run with a different user or group than the caller (`execve` with `-C uid!=euid` or `-C gid!=egid`), and programs running as root (`-F euid=0`, `-F egid=0`)

Example, 64-bit permission changes:
```
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
```

```bash
sudo chmod 0600 /etc/audit/rules.d/stig-syscalls.rules
sudo augenrules --load
sudo auditctl -l | wc -l
```

### The extended attribute rules need two lines each
The permission-change rules for extended attributes passed for regular users only after I added a second copy of each line with `-F auid=0` instead of `-F auid>=1000 -F auid!=unset`. The STIG wants both: regular users and root.

### Verify
- Fixes 19 to 21 add 59 audit rules across the three files `stig-privileged.rules`, `stig-watches.rules` and `stig-syscalls.rules`.
- Rescan after this step: **72.15%**, 157 passed, 57 failed.

---

## Fix 22: Password quality, password age and session limits

**Rules:** the password quality rules (`pwquality`), `accounts_maximum_age_login_defs`, `accounts_minimum_age_login_defs`, `accounts_umask_etc_login_defs`, `accounts_max_concurrent_login_sessions`

### The finding
`pam_pwquality` was installed (Fix 8) but not configured, and the password age, default file permissions and login limits were at Ubuntu defaults.

### Why it matters
Longer and more varied passwords are harder to guess. Password age limits force a change. A `077` umask means new files are private by default. A login limit stops one account from opening unlimited sessions.

### Safety first
These change login behavior. Keep one SSH session open while you test, and keep the VM console available.

### The fix
```bash
sudo apt install -y libpam-pwquality
```
Then set these values in `/etc/security/pwquality.conf` (remove the `#` if the line is commented out):
```
minlen = 15
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
dictcheck = 1
enforcing = 1
```
- `minlen = 15`: at least 15 characters.
- `dcredit`, `ucredit`, `lcredit`, `ocredit` at `-1`: at least one digit, one uppercase letter, one lowercase letter and one symbol.
- `difok = 8`: a new password must differ from the old one by at least 8 characters.
- `dictcheck = 1` rejects dictionary words. `enforcing = 1` applies the rules to everyone, including root.

In `/etc/login.defs`, set:
```
PASS_MAX_DAYS 60
PASS_MIN_DAYS 1
UMASK 077
```

```bash
echo '* hard maxlogins 10' | sudo tee /etc/security/limits.d/stig-maxlogins.conf
```

### Verify
- `grep -E '^(minlen|dcredit|ucredit|lcredit|ocredit|difok|dictcheck|enforcing)' /etc/security/pwquality.conf` shows all eight lines.
- `grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|UMASK)' /etc/login.defs` shows the three values.
- `cat /etc/security/limits.d/stig-maxlogins.conf` shows `* hard maxlogins 10`.

### Lesson learned: `UMASK 077` makes files created by root private
After this change, a scan report written by `sudo oscap ...` is readable by root only, so `scp` from my computer fails with "Permission denied." On the VM, run `sudo chown <user>:<user> ~/report-<name>.html` first, then copy it.

---

## Fix 23: Audit daemon settings and audit log permissions

**Rules:** the `auditd` log group, free-space warning and action rules, and the audit log file permission rules

### The finding
`/etc/audit/auditd.conf` used the default log group and free-space settings, and the audit log files could be read by more people than the STIG allows.

### Why it matters
The audit log is the record of what happened. It should be private, and the system should warn an administrator before the disk fills up and logging stops.

### The fix
In `/etc/audit/auditd.conf`, set:
```
log_group = root
space_left = 25%
space_left_action = email
```

```bash
sudo chgrp root /var/log/audit/*
sudo chmod 0600 /var/log/audit/*
sudo service auditd restart
```
- `service auditd restart` is used because `systemctl restart auditd` is refused on some systems.

### Verify
- `sudo ls -l /var/log/audit/` shows `-rw-------` and group `root` on each log file.

### Regression found after the 75.3% scan: the directory itself
With `log_group = root`, the rule `directory_permissions_var_log_audit` wants the **folder** `/var/log/audit` at `0700`. It was at `0750`, so a rule that passed before the change failed after it.

```bash
sudo chmod 0700 /var/log/audit
sudo ls -ld /var/log/audit
```
- Expected: `drwx------`.
- A November 11 rescan around 9:25 PM Mountain confirmed this change: 35 rules failed, down from 36 on the 75.3% scan. I did not record the weighted score or the pass count for that first November 11 scan.

---

## Rescans on November 3, 2026

| Time (Mountain) | Weighted score | Passed | Failed | What changed |
|---|---|---|---|---|
| About 5:07 PM | 68.74% | 98 | 116 | Fixes 17 and 18 (ssh-agent and ssh-keysign audit rules; every SSH rule now passes) |
| About 5:34 PM | 72.15% | 157 | 57 | Fixes 19 to 21: 59 audit rules in total |
| About 5:54 PM | **75.3%** | 178 | 36 | Fixes 22 and 23 and the extended attribute follow-up: 23 rules newly passing, 1 rule regressed |

Two earlier full scans on November 2 scored 68.73% (96 passed) and then 67.95% (97 passed).

Why the score does not rise one-for-one: it is weighted, so each rule counts for a different amount. The step from 98 to 157 passed rules (59 more) moved the score by 3.4 points, while the next 21 passed rules added 3.2 points.

---

## Lessons learned on November 3

- Every file in `/etc/audit/rules.d/` must be `0600`. `0640` fails the earlier rules.d permission rule.
- Extended attribute audit rules need two lines each: one for regular users (`auid>=1000`) and one for root (`auid=0`).
- The scanner wants the exact, ordered SSH encryption lists from the STIG fix script, not the text in the rule description.
- The weighted score does not rise one-for-one with rules passed.
- With `UMASK 077`, files root creates (including scan reports) are root-only. `chown` them before `scp`.
- A fix can break a rule that already passed. Compare two scans rule by rule (for example, with a short script that reads the two HTML reports) instead of only reading the score.
- The audit immutable rule (`-e 2`) goes last. It locks the audit rules until the next reboot, so any later change to them needs a restart.

## Opening the November 11, 2026 session

The `/var/log/audit` permission fix from Fix 23 had not been rescanned. After starting the VM and taking a snapshot, I ran a full profile scan around 9:25 PM Mountain:

```bash
cd ~/scap-security-guide-0.1.82
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ~/results-nov11.xml --report ~/report-nov11.html ssg-ubuntu2404-ds.xml
```

oscap prints pass or fail for each rule, but not the overall score. To list the failing rule names, and later to read the score and the result counts:

```bash
sudo python3 -c "import re,sys;d=open(sys.argv[1]).read();print('\n'.join(sorted(set(re.findall(r'content_rule_([^\"]+)\"[^>]*>\s*<result>fail',d)))))" ~/results-nov11.xml
sudo grep -o '<score[^>]*>[^<]*' ~/results-nov11.xml
sudo grep -o '<result>[a-z]*' ~/results-nov11.xml | sort | uniq -c
```

The first scan found 35 failing rules, down from 36. That confirmed the audit-folder fix had taken. I did not record the weighted score or the pass count for this scan.

---

## Fix 24: Password delay, hashing, empty passwords, and account expiration

**Rules:** `account_disable_post_pw_expiration`, `accounts_passwords_pam_faildelay_delay`, `no_empty_passwords`, `accounts_password_pam_unix_rounds_password_auth`, `set_password_hashing_algorithm_auth_stig`

### The finding

Accounts stayed usable after the password expired, a failed login had no delay, empty passwords were still allowed in PAM, and password hashing was not at the STIG values.

### Why it matters

A short delay after a bad password slows guessing. Stronger hashing (SHA-512 with 100000 rounds) makes stolen password files harder to crack. Removing empty-password logins closes a bypass. Disabling an account 35 days after the password expires limits how long a stale account can be used.

### Safety first

These change login settings. Take a snapshot first: `qm snapshot <vmid> <snapshot-name>`. Keep the current SSH session open the whole time. Test a fresh login and `sudo -v` from a **second** window before you close anything.

### The fix

I let the scanner apply its own fixes, including the package-cleanup rule in Fix 25, in one command. From `~/scap-security-guide-0.1.82`:

```bash
sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig \
 --rule xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration \
 --rule xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faildelay_delay \
 --rule xccdf_org.ssgproject.content_rule_no_empty_passwords \
 --rule xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_rounds_password_auth \
 --rule xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_auth_stig \
 --rule xccdf_org.ssgproject.content_rule_clean_components_post_updating \
 --results ~/results-batchA.xml ssg-ubuntu2404-ds.xml
```

What the scanner set:

- `INACTIVE=35` in `/etc/default/useradd` (disable the account 35 days after the password expires)
- a 4-second delay after a failed password (`pam_faildelay` `delay=4000000`, configured through `pam-auth-update`)
- `nullok` removed, so empty passwords are not accepted
- `rounds=100000` and SHA-512 for password hashing

### Verify

- In a **second** window, open a new SSH session and run `sudo -v`. If both work, the login path is still safe.
- A later full rescan (after Fix 26) showed these five rules had passed.

---

## Fix 25: Clean unused packages after updates

**Rule:** `clean_components_post_updating`

### The finding

Unused packages and old kernels could be left behind after updates.

### Why it matters

Leftover packages add attack surface and clutter. The STIG wants unattended upgrades to remove unused dependencies and kernels.

### The fix

Applied in the same `--remediate` command as Fix 24. The scanner configured unattended-upgrades to remove unused dependencies and kernels.

### Verify

Confirmed on the same later full rescan as Fix 24.

---

## Fix 26: Chrony time servers

**Rules:** `chronyd_server_directive`, `chronyd_or_ntpd_set_maxpoll`, `chronyd_sync_clock`. `chronyd_specify_remote_server` stays failed, as a documented exception.

### The finding

Fix 15 installed chrony and removed timesyncd, but the time-server settings still failed. The STIG wants `server` lines (not Ubuntu's default `pool` lines), `makestep 1 -1`, and `maxpoll 16`. It also wants one specific military time server.

### Why it matters

Accurate, consistent time matters for audit logs, log correlation and certificate checks. A clock with no source is worse than a clock synced to a public server.

### Safety first

This does not touch SSH. Take a snapshot anyway if you do not already have one from the start of the session.

### The fix

I first pointed chrony at the STIG's required server, `0.us.pool.ntp.mil`, commented out the `pool` lines, and set `makestep 1 -1`. That name did not resolve from the home network (`getent hosts 0.us.pool.ntp.mil` printed nothing). `chronyc sources` showed no sources at all, so the clock was unsynced.

I then switched to public NIST servers, which still satisfy three of the four time-sync rules. On a stock chrony config (pool lines, and no leftover `.mil` line), this is enough:

```bash
sudo sed -i 's/^pool /#pool /; s/^makestep.*/makestep 1 -1/' /etc/chrony/chrony.conf
echo "server time.nist.gov iburst maxpoll 16" | sudo tee -a /etc/chrony/chrony.conf
echo "server time-a-g.nist.gov iburst maxpoll 16" | sudo tee -a /etc/chrony/chrony.conf
sudo systemctl restart chrony && sleep 20 && chronyc sources
```

If a leftover `server 0.us.pool.ntp.mil` line is still in the file, replace or delete it first so the clock is not pointed at an unreachable host:

```bash
sudo sed -i 's/^server 0.us.pool.ntp.mil.*/server time.nist.gov iburst maxpoll 16/' /etc/chrony/chrony.conf
```

The important check is `chronyc sources`.

### Verify

`chronyc sources` showed:

- `^- time-a-wwv.nist.gov` (what `time.nist.gov` resolved to), stratum 1
- `^* time-a-g.nist.gov`, stratum 1, meaning chrony was locked onto that server

The later full rescan passed `chronyd_server_directive`, `chronyd_or_ntpd_set_maxpoll` and `chronyd_sync_clock`. `chronyd_specify_remote_server` still failed, because the scanner only accepts that exact `.mil` server. That rule is a documented exception: the required server is not reachable outside government networks.

### Lesson learned

Verify a fix actually works, not just that the scanner would pass. An unreachable time server would have left the clock with no source. Check name resolution (`getent hosts`) and look for `^*` or `^+` in `chronyc sources` before you move on.

---

## Rescan after Fixes 24 to 26: 79.15%

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ~/results-nov11b.xml --report ~/report-nov11b.html ssg-ubuntu2404-ds.xml
sudo grep -o '<score[^>]*>[^<]*' ~/results-nov11b.xml
sudo grep -o '<result>[a-z]*' ~/results-nov11b.xml | sort | uniq -c
```

Weighted score **79.15%** (raw score 79.151375): 188 passed, 26 failed, 20 not applicable. That is 9 of the 10 rules in this batch. The tenth is the military time-server exception.

---

## Fix 27: Packages, log and library permissions, AIDE, and audit at boot

**Rules:** `package_audit-audispd-plugins_installed`, `package_nss_sss_installed`, `package_pam_sss_installed`, `dir_permissions_system_journal`, `file_permissions_var_log_stig`, `root_permissions_syslibrary_files`, `aide_check_audit_tools`, `aide_disable_silentreports`, `aide_build_database`, `grub2_audit_argument`

### The finding

Three packages were missing, some log and library permissions had failed again or had never fully passed, AIDE (the file integrity checker) was not set up, and audit was not enabled from the moment the system boots.

### Why it matters

AIDE notices when important files change. Tight log and library permissions protect the evidence and the system libraries. The audit boot argument means audit starts before user space, so early events are not missed. The extra packages are what later smart-card and directory-service rules expect.

### Safety first

These are low-risk compared with sudo or a boot-loader password, but one of the packages touches login settings. Take a snapshot first. Keep the current SSH session open and test a fresh login and `sudo -v` in a second window before you reboot.

### The fix

From `~/scap-security-guide-0.1.82`, let the scanner apply its own fixes:

```bash
sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig \
 --rule xccdf_org.ssgproject.content_rule_package_audit-audispd-plugins_installed \
 --rule xccdf_org.ssgproject.content_rule_package_nss_sss_installed \
 --rule xccdf_org.ssgproject.content_rule_package_pam_sss_installed \
 --rule xccdf_org.ssgproject.content_rule_dir_permissions_system_journal \
 --rule xccdf_org.ssgproject.content_rule_file_permissions_var_log_stig \
 --rule xccdf_org.ssgproject.content_rule_root_permissions_syslibrary_files \
 --rule xccdf_org.ssgproject.content_rule_aide_check_audit_tools \
 --rule xccdf_org.ssgproject.content_rule_aide_disable_silentreports \
 --rule xccdf_org.ssgproject.content_rule_aide_build_database \
 --rule xccdf_org.ssgproject.content_rule_grub2_audit_argument \
 --results ~/results-batchC.xml ssg-ubuntu2404-ds.xml
```

The scanner first reports `fail` for each rule, then "Starting Remediation." Building the AIDE database can take 5 to 10 minutes with no output. Let it finish. The `grub2_audit_argument` change only takes effect after a reboot.

### Verify

- Test `sudo -v` from a fresh window, then `sudo reboot`, and reconnect.
- Full rescan after the reboot (below).

### Lesson learned

Installing the SSSD packages (`package_nss_sss_installed` and `package_pam_sss_installed`) made 7 previously not-applicable rules start to apply. Those are the SSSD configuration rules that expect a smart card or a company directory. The packages themselves are required, but the fail count will not drop as far as the pass count rises.

---

## Rescan after Fix 27: 85.87%

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ~/results-nov11c.xml --report ~/report-nov11c.html ssg-ubuntu2404-ds.xml
sudo grep -o '<score[^>]*>[^<]*' ~/results-nov11c.xml
sudo grep -o '<result>[a-z]*' ~/results-nov11c.xml | sort | uniq -c
```

Weighted score **85.87%** (raw score 85.873016): 198 passed, 23 failed, 13 not applicable. Passes went up by 10, but failures only dropped by 3, because not-applicable went from 20 to 13.

---

## Fix 28: Log file permissions after reboot, and sudo audit events

**Rules:** `file_permissions_var_log_stig`, `audit_sudo_log_events`

### The finding

`file_permissions_var_log_stig` failed again after the Fix 27 reboot, when the system created new log files. Attempts to perform maintenance with sudo were also not being recorded.

### Why it matters

New log files can be created more open than the STIG allows, so a permission fix does not always last across a reboot. Logging sudo use records who ran privileged commands.

### Safety first

Low risk. Keep the current SSH session open anyway.

### The fix

```bash
sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig \
 --rule xccdf_org.ssgproject.content_rule_file_permissions_var_log_stig \
 --rule xccdf_org.ssgproject.content_rule_audit_sudo_log_events \
 --results ~/results-batchD.xml ssg-ubuntu2404-ds.xml
```

Expected: `Result fixed` for both rules.

### Verify

A list of failing rules taken from the older `~/results-nov11c.xml` file will still show these two names. Rescan to a new file:

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results ~/results-nov11d.xml --report ~/report-nov11d.html ssg-ubuntu2404-ds.xml
sudo grep -o '<score[^>]*>[^<]*' ~/results-nov11d.xml
```

---

## Rescans on November 11, 2026

All times are Mountain.

| Time (Mountain) | Weighted score | Passed | Failed | What changed |
|---|---|---|---|---|
| About 9:25 PM | not recorded | not recorded | 35 | Confirmed the Fix 23 `/var/log/audit` permission change |
| After Fixes 24 to 26 | **79.15%** | 188 | 26 | Password, package-cleanup and chrony rules. The military time-server rule still failed, by design |
| After Fix 27 and a reboot | **85.87%** | 198 | 23 | Packages, log and library permissions, AIDE, and audit at boot. 10 more passed, but only 3 fewer failed |
| About 9:48 PM, after Fix 28 | **86.43%** | not recorded | 21 | Log permissions re-applied after the reboot, and sudo use now logged. Raw score 86.428566 |

The session started at 75.3% (178 passed, 36 failed) from November 3 and ended at 86.43%. I did not capture the exact pass count for the final scan, so I do not claim one.

---

## Lessons learned on November 11

- Verify a fix actually works, not just that the scanner would pass. An unreachable time server left the clock with no source until I switched to NIST and confirmed `^*` in `chronyc sources`.
- Installing packages can make previously not-applicable rules start to apply. After Fix 27, 10 more rules passed but only 3 fewer failed, because not-applicable dropped from 20 to 13.
- `/var/log` permission fixes can fail again after a reboot, when the system creates new log files. Rescan after the reboot, and be ready to re-apply the rule.
- oscap does not print the overall score to the terminal. Read it from the results file (`grep` for `<score`), and use a new results file when you list remaining failures, or you will see stale names from an older scan.
- Keep a safety SSH session open and test a fresh login plus `sudo -v` whenever a batch touches login settings.

## Next up: the 21 rules still failing (as of the 86.43% scan)

"Done" means every remaining rule either passes or is written up as an accepted exception with a reason.

**Planned exceptions (13 rules):**

- **Smart card login:** `install_smartcard_packages`, `smartcard_configure_ca`, `smartcard_configure_cert_checking`, `smartcard_configure_crl`, `smartcard_pam_enabled`
- **SSSD** (the service that links logins to a smart card or a company directory, which a standalone home lab does not have): `service_sssd_enabled`, `sssd_certification_path_trust_anchor`, `sssd_enable_pam_services`, `sssd_enable_smartcards`, `sssd_enable_user_cert`, `sssd_offline_cred_expiration`
- **FIPS mode:** `is_fips_mode_enabled`
- **Military time server:** `chronyd_specify_remote_server` (see Fix 26)

**Real fixes still to do (8 rules):**

- **Boot loader password** (next session, lockout risk, snapshot first): `grub2_password`, `grub2_uefi_password`
- **sudo authentication** (next session, lockout risk, snapshot first): `sudo_remove_nopasswd`, `sudo_require_authentication`
- **Remote logging and audit offload** (need a log receiver, possibly a small container): `rsyslog_remote_access_monitoring`, `auditd_audispd_configure_remote_server`, `auditd_offload_logs`
- **Audit, last:** `audit_rules_immutable`

After those, automate the confirmed fixes with Ansible.

---

## Score history (weighted)

| After | oscap score | Passed | Failed | Notes |
|---|---|---|---|---|
| Baseline | 51.38% | 54 | 65 | 45% pass rate on applicable rules |
| Fix 6 | 60.03% | not recorded | not recorded | |
| Fix 10 | 61.22% | not recorded | not recorded | |
| Fix 11 | 62.02% | not recorded | not recorded | |
| Fix 16 | 68.60% | not recorded | not recorded | |
| Nov 2, full scan | 68.73% | 96 | not recorded | |
| Nov 2, later scan | 67.95% | 97 | not recorded | slightly lower: see the note below |
| Nov 3, about 5:07 PM | 68.74% | 98 | 116 | Fixes 17 and 18 |
| Nov 3, about 5:34 PM | 72.15% | 157 | 57 | Fixes 19 to 21 |
| Nov 3, about 5:54 PM | 75.3% | 178 | 36 | Fixes 22 and 23 |
| Nov 11, about 9:25 PM | not recorded | not recorded | 35 | Confirmed the Fix 23 audit-folder permission change |
| Nov 11, after Fixes 24 to 26 | 79.15% | 188 | 26 | Password, package-cleanup and chrony rules |
| Nov 11, after Fix 27 and a reboot | 85.87% | 198 | 23 | Packages, permissions, AIDE, audit at boot |
| Nov 11, about 9:48 PM, after Fix 28 | 86.43% | not recorded | 21 | Log permissions re-applied, sudo use logged |

The score went down a little between the two November 2 scans (68.73% to 67.95%) even though one more rule passed. I did not compare the two reports rule by rule, so I do not know which rule caused it. I report it as it happened.

Package-install rules are low weight, so the score moves slowly. Fixes 12 to 16 (SSH settings, kernel settings, firewall, time sync, log permissions) added about 6.6 points in one session. The November 11 session (Fixes 24 to 28) moved the weighted score from 75.3% to 86.43%. Remaining real fixes are the boot loader password, sudo authentication, remote logging, and the audit immutable rule last (see "Next up" above).

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
