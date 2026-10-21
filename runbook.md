# Ubuntu 24.04 STIG Hardening Runbook

How to use this: work through each finding in order. Run the commands on the target server, then run the verify step. Every finding is tied to the rule title in the OpenSCAP report.

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
