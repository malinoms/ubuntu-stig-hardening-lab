# Lab Notes: AI-Assisted STIG Hardening

**Premise:** These notes show how I worked with an AI assistant to harden an Ubuntu server to the DISA STIG, and they are clear about who did what. The AI handled speed and breadth (building, scanning, scripting, explaining). I owned the risk decisions, verified the work, and learned enough to defend every change.

**Tags used below:** [AI] the assistant did it, [Me] my decision or action, [Both] worked out together. **Decision point** flags a judgment call a human had to own.

**Environment:** Proxmox VE 9.2 (6 CPU cores, 11 GB RAM) on a home lab server. Lab VMs sit on an isolated internal bridge (`<lab-subnet>`), separate from my home network.

Placeholders: `<vmid>` is the lab VM's Proxmox ID, `<user>` is the VM admin account, `<lab-vm>` is the VM's address, `<lab-subnet>` is the isolated lab network, and `<home-lan>` is my home network.

---

## Step 1: Get the Ubuntu 24.04 cloud image [AI]
- **Why:** The official cloud image is prebuilt for VMs. It skips a manual install and gives a consistent, reproducible baseline.
- **Command:** `wget -P /var/lib/vz/template/iso https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img`
- **Result:** 593 MB downloaded.

## Step 2: Create the VM [AI]
- **Why:** cloud-init sets the user, SSH key, and static IP on first boot, so no console clicking is needed.
- **Command:** `qm create <vmid> --name <vm-name> --memory 2048 --cores 2 --net0 virtio,bridge=<lab-bridge> --scsihw virtio-scsi-pci --scsi0 local-lvm:0,import-from=<image> --ide2 local-lvm:cloudinit --boot order=scsi0 --serial0 socket --vga serial0 --ciuser <user> --sshkeys <authorized-keys-file> --ipconfig0 ip=<lab-vm>/24,gw=<lab-gateway>`, then `qm disk resize <vmid> scsi0 20G`
- **Result:** A VM with 2 vCPUs, 2 GB RAM, and a 20 GB disk on the lab network.

## Step 3: Give the lab internet access without exposing the home network [Both]
- **Finding:** The lab bridge was fully sealed (`ip_forward=0`, `bridge-ports none`). That is good for isolation, but the VMs couldn't get patches or scanning tools.
- **Decision point [Me]:** I chose NAT over manual file transfer. I approved NAT for outbound internet only, with an explicit drop rule for lab traffic headed to my home LAN. Any deliberately vulnerable practice VMs stay powered off while NAT is enabled.
- **Changes** (made persistent in `/etc/network/interfaces` under the lab bridge, with a backup taken first):
  - `echo 1 > /proc/sys/net/ipv4/ip_forward`
  - `iptables -t nat -A POSTROUTING -s <lab-subnet> -o <uplink-bridge> -j MASQUERADE`
  - `iptables -I FORWARD -s <lab-subnet> -d <home-lan> -j DROP`
- **DNS:** The VM uses public DNS resolvers, so it doesn't need the home router.
- **Security note:** Segmentation is a STIG theme in its own right. Lab or untrusted systems shouldn't be able to reach production, and this setup mirrors that principle.

## Step 4: Snapshot, patch, and install the scanner [AI]
- `qm snapshot <vmid> baseline` saved a rollback point before any changes.
- Patched with `apt full-upgrade`, then installed `openscap-scanner` (OpenSCAP 1.3.9).
- Content: ComplianceAsCode SCAP Security Guide v0.1.82, file `ssg-ubuntu2404-ds.xml`, profile `xccdf_org.ssgproject.content_profile_stig` (DISA STIG for Ubuntu 24.04).
- **Note:** The server was patched before the baseline scan, so "before" means a stock but up-to-date server.

## Step 5: Baseline scan (before hardening) [AI]
- **Command:** `sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results baseline.xml --report baseline.html ssg-ubuntu2404-ds.xml`
- **Results:** 54 pass, 65 fail, 116 not applicable, 4 not checked, 0 errors.
- **Compliance among applicable rules:** 54 of 119 rules pass, or about **45%**. (The oscap weighted score for the same scan was 51.38%. See `results/summary.md`.)
- **Notable failures:** no file-integrity monitoring (AIDE), FIPS mode off, sudo with NOPASSWD (the cloud-image default), no DoD login banner for SSH, no password-quality module (pam_pwquality), and no delay after failed logons.
- **Evidence:** the raw reports are kept privately because they contain host details. The counts are in `results/summary.md`.

## Turning point: "Am I actually learning?" [Me]
- After the baseline scan, I stopped to ask whether I was learning or just watching the AI work. Honest answer: mostly watching.
- **Decision point [Me]:** I changed roles for the hardening phase. I make the fixes myself, and the AI acts as instructor and verifier. It explains each finding, gives hints before answers, rescans to confirm, and logs the work.
- **Decision point [Me]:** I reframed the project to show human and AI teamwork, not just the STIG results.
- **Lesson:** AI speed is only valuable if the human understands enough to catch a wrong answer and own the risk.

## Step 6: Lockout and recovery [Both]
- **[AI] mistake:** The fix script for the confirmation banner was generated with `--rule`, but oscap ignored it and produced the full STIG profile (30,066 lines). It was run without checking its size.
- **Result:** Hundreds of changes at once, including enabling the ufw firewall, which blocked SSH (port 22), and smart card login rules. SSH hung.
- **[Me]** I logged in through the Proxmox VM console (after the AI set a temporary password via cloud-init), found the cause myself (`sudo ufw status` showed active, with no rule for port 22), opened port 22, and confirmed SSH worked again.
- **Decision point [Me]:** I rolled back to the `baseline` snapshot instead of keeping a box full of undocumented changes. Then I re-patched, took a `patched` snapshot, reinstalled the scanner, and redid Fix 1 from the runbook.
- **Lessons:** Snapshot before every change. Keep a console path open. Check what a script will do (`wc -l`) before running it. "No error" doesn't mean it worked.

## Step 7: Fix 2, confirmation prompt [Me]
- **[Me] caught it:** I regenerated the fix and checked `wc -l` first. It was 30,066 lines again, so I didn't run it. The length check prevented a second lockout.
- **[AI]** Found a method that respects `--rule`: `oscap xccdf eval --remediate --rule ...`. Result: fail, then fixed.
- **[Me] verified both paths:** `y` lets you in, `n` closes the connection. The rescan passed.
- **[Both] Security housekeeping:** I rotated the lab SSH key. I generated a new key on my workstation, added it to the Proxmox host and the VM, then removed the old key from both (with backups kept) and confirmed SSH still worked in a fresh window.

## Step 8: Snapshot before the next fix [Me]
- **[Me]** Took the snapshot `after-key-cleanup` from the Proxmox host shell (`qm snapshot <vmid> ...`) and confirmed the chain with `qm listsnapshot <vmid>`: baseline, patched, after-key-cleanup.

## Step 9: Fix 3, disable Ctrl+Alt+Del reboot [Me]
- **[AI]** Picked a low-risk, non-SSH finding next to avoid any lockout risk.
- **[Me]** Checked the state first (`systemctl status ctrl-alt-del.target` pointed at `reboot.target`), masked it, reloaded systemd, and verified `Loaded: masked`.

## Step 10: Fix 4, account lockout after 3 failed passwords [Me]
- **[Me]** Took the snapshot `before-faillock`, found `deny = 3` commented out, and fixed only this rule with `oscap xccdf eval --remediate --rule ...` (fail, then fixed).
- **[Me] verified:** rechecked `faillock.conf` for `deny = 3`, then confirmed the `pam_faillock.so` preauth and authfail lines in `/etc/pam.d/common-auth`.
- **[Both] Decision:** We didn't test a live lockout, to avoid locking `sudo`. The recovery command is documented in the runbook instead.

## Step 11: Fix 5, idle session timeout [Me]
- **[Me]** Found no timeout (`echo $TMOUT` was blank) and fixed only this rule with `oscap ... --remediate --rule accounts_tmout` (fail, then fixed).
- **[Me] noticed** the old window still showed blank after the fix. Lesson: login settings only load in a new session.
- **[Me] verified** in a new SSH session: `TMOUT=600` (10 minutes). **[AI] correction:** the AI had said 15 minutes. The STIG value is 10, and my result showed the right number.

## Step 12: Fix 6, audit system [Both]
- **[Me]** Found auditd missing, installed it with `apt`, then verified with the scanner (both rules pass).
- **[AI] mistake:** guessed the rule name (`package_auditd_installed`) and got "not found." **[Both]** searched the STIG datastream with `grep` and found the real names (`package_audit_installed`, `service_auditd_enabled`).
- **Lesson:** Look up rule IDs in the content instead of guessing. Use a variable (`P=...`) so long commands don't break when pasted.

## Step 13: Rescan after six fixes [Me]
- **[Me]** Ran a full STIG scan (`--results after-fix6.xml --report after-fix6.html`), saved on the lab VM.
- **Score: 60.03%** (oscap score), up from 51.38% on the baseline scan by the same measure. The baseline pass rate among applicable rules was about 45%.
