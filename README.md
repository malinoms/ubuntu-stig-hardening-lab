# Ubuntu 24.04 STIG Hardening Lab

I took a fresh Ubuntu 24.04 server and hardened it against the DISA STIG using OpenSCAP and the SCAP Security Guide (ComplianceAsCode) 0.1.82, one rule at a time, in my Proxmox home lab. The goal was to learn what each control does and to make each change deliberately: weigh the risk, keep a way back, and verify the result, not just raise a number. This repo holds the runbook I wrote as I went, my lab notes (including the mistakes), and a summary of the scan results.

## Results

| Scan | Pass rate (applicable rules) | oscap score |
|---|---|---|
| Baseline, stock patched server | 45% (54 of 119) | 51.38% |
| After six fixes | not recorded | 60.03% |
| After Fix 10 | not recorded | 61.22% |
| After Fix 11 | not recorded | 62.02% |
| After sixteen fixes | not recorded | 68.60% |
| Nov 2, later full scans | 96 and 97 passed | 68.73%, then 67.95% |
| Nov 3, about 5:07 PM | 98 passed, 116 failed | 68.74% |
| Nov 3, about 5:34 PM | 157 passed, 57 failed | 72.15% |
| Nov 3, about 5:54 PM | 178 passed, 36 failed | 75.3% |

The oscap score went from **51.38% to 75.3%** across twenty-three fixes. The baseline pass rate and the oscap score are measured differently, and I only kept the pass rate for the baseline. The 75.3% scan was taken before one last permission fix (`/var/log/audit`, see Fix 23), so I have not rescanned that yet. Details are in [results/summary.md](results/summary.md).

## The twenty-three fixes

Rule IDs are shown without the `xccdf_org.ssgproject.content_rule_` prefix.

| Fix | What it does | Rule IDs |
|---|---|---|
| 1 | DoD notice-and-consent banner before SSH login | `banner_etc_issue_net`, `sshd_enable_warning_banner_net` |
| 2 | Login confirmation prompt that ends the session unless the user agrees | `banner_etc_profiled_ssh_confirm` |
| 3 | Disable the Ctrl+Alt+Del reboot | `disable_ctrlaltdel_reboot` |
| 4 | Lock accounts after 3 failed password attempts | `accounts_passwords_pam_faillock_deny` |
| 5 | Log out idle shells after 10 minutes (TMOUT=600) | `accounts_tmout` |
| 6 | Install and enable the audit system | `package_audit_installed`, `service_auditd_enabled` |
| 7 | Restrict the audit rules file to root | `file_permissions_etc_audit_rulesd` |
| 8 | Install the password-quality module | `package_pam_pwquality_installed` |
| 9 | Install vlock so users can lock their session | `vlock_installed` |
| 10 | Install smart-card (OpenSC) support | `package_opensc_installed` |
| 11 | Require a password for sudo | `sudo_remove_nopasswd` |
| 12 | SSH daemon settings: keepalive, idle timeout, no empty passwords, no X11 forwarding, no user environment, pubkey auth | `sshd_set_keepalive`, `sshd_set_idle_timeout`, `sshd_disable_empty_passwords`, `sshd_disable_x11_forwarding`, `sshd_x11_use_localhost`, `sshd_do_not_permit_user_env`, `sshd_enable_pubkey_auth` |
| 13 | Kernel settings (SYN cookies, dmesg restriction, ASLR) and block USB storage | `sysctl_net_ipv4_tcp_syncookies`, `sysctl_kernel_dmesg_restrict`, `sysctl_kernel_randomize_va_space`, `kernel_module_usb-storage_disabled` |
| 14 | Enable the ufw firewall (deny incoming) with a rate-limited SSH rule | `check_ufw_active`, `ufw_rate_limit` |
| 15 | Replace systemd-timesyncd with chrony | `package_chrony_installed`, `package_timesyncd_removed` |
| 16 | Tighten journal, `journalctl` and `/var/log` permissions | `dir_permissions_system_journal`, `file_permissions_journalctl`, `file_permissions_var_log_stig` |
| 17 | Audit rules that log `ssh-agent` and `ssh-keysign` use | audit rules for `ssh-agent` and `ssh-keysign` |
| 18 | No root login over SSH, and the exact approved encryption lists | `sshd_disable_root_login`, `sshd_use_approved_ciphers_ordered_stig`, `sshd_use_approved_macs_ordered_stig`, `sshd_use_approved_kex_ordered_stig` |
| 19 | Audit rules for 17 privileged commands plus `fdisk` and `modprobe` | the privileged-command audit rules |
| 20 | Audit watches on account, login-record and cron files (15 paths) | the file-watch audit rules |
| 21 | Audit rules for system calls: permission changes, deletes, failed access, kernel modules, privilege use | the system-call audit rules |
| 22 | Password quality, password age, default file permissions (`UMASK 077`) and a limit of 10 logins | `pwquality` rules, `accounts_maximum_age_login_defs`, `accounts_minimum_age_login_defs`, `accounts_umask_etc_login_defs`, `accounts_max_concurrent_login_sessions` |
| 23 | Audit daemon log group and free-space settings, and private audit logs | the `auditd.conf` and audit log permission rules |

## Method

For each finding:

1. Take a Proxmox snapshot of the VM before changing anything.
2. Check the current state by hand so I understand the finding.
3. Fix only that rule: `sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --rule <rule-id> ssg-ubuntu2404-ds.xml`
4. Verify the change by hand, then rescan the single rule to confirm it passes.
5. After a batch of fixes, run a full profile scan.

## Key decisions

The commands are the easy part. These are the calls that mattered.

**Snapshot before every change, and keep a console path.** Any hardening change can break access or leave the system in a state I don't understand. I could fix forward when something broke, or make every change reversible. I took a Proxmox snapshot before each fix and kept the VM console available as a way in that doesn't depend on SSH. When a change did lock me out, the console got me back in and the snapshots gave me a clean place to return to.

**Remediate one rule at a time.** I could apply the whole STIG profile at once or fix one rule at a time. Early on, `oscap xccdf generate fix --rule` ignored `--rule` and wrote about 30,000 lines for the entire profile, and running it enabled the firewall without an SSH rule and locked me out. I rolled back to a clean snapshot instead of keeping a server full of undocumented changes, then switched to `oscap xccdf eval --remediate --rule`, which respects the filter, and I now run `wc -l` on any generated script before I run it.

**Look up rule IDs instead of guessing.** A guessed rule name returned "not found" and wasted a step. I search the datastream for the real IDs instead: `grep -o 'content_rule_[a-z_]*audit[a-z_]*' ssg-ubuntu2404-ds.xml | sort -u`. It takes seconds and removes the guesswork.

**Document the faillock recovery instead of testing a live lockout.** After setting accounts to lock after 3 failed passwords, I could prove it with a real lockout or verify the configuration. A live test would lock `sudo` on my admin account. I verified the `faillock.conf` and PAM lines, and I documented the recovery command (`sudo faillock --user <user> --reset` from the VM console), accepting slightly less proof for much less risk.

**Verify every change by hand.** "No error" doesn't mean a change worked, so I check the actual system state after each fix and rescan the rule. For TMOUT, the old window still showed it blank, and only a new session showed `600`, because login settings apply to new sessions. I treat tool output and AI suggestions as inputs to check: an assistant's guesses on a rule name and on the timeout value were both wrong, and verifying against the system caught both.

**Report the scores honestly.** OpenSCAP reports a weighted score, and the simple pass rate is a different number. The baseline was a 45% pass rate (54 of 119 applicable rules) but a 51.38% weighted score, and the latest scan scored 75.3% weighted (178 rules passed, 36 failed). I report the weighted scores side by side (51.38% to 75.3%) rather than quoting 45% to 75.3%, which would compare two different measures. I didn't record per-rule counts for the scans before November 3, so I don't claim any. The score also does not rise one-for-one with rules passed: 59 more rules passing moved it only 3.4 points.

**Isolate the lab network from the home LAN.** The lab VMs needed internet for patches and tools, but I didn't want them reaching my home network. I chose NAT over copying files in by hand, allowed outbound traffic only, added an explicit rule dropping lab traffic to my home LAN, and keep deliberately vulnerable practice VMs powered off while NAT is on. That gave me patching without giving up segmentation.

**Things that surprised me on November 3.** Files in `/etc/audit/rules.d/` must be `0600`; `0640` made an earlier rule fail again. The extended-attribute audit rules need one line for regular users and a second for root. With `UMASK 077`, scan reports created by root are root-only, so I `chown` them before copying them off the VM. The scanner wants the exact, ordered SSH encryption lists from the STIG fix script, not the text in the rule description. And one fix (`log_group = root`) quietly broke a rule that already passed, which I only caught by comparing two scans rule by rule. I save the audit "immutable" rule (`-e 2`) for last, because it locks the audit rules until the next reboot.

## Repo layout

```
.
├── README.md            this overview
├── runbook.md           step-by-step commands and checks for Fixes 1 to 23
├── lab-notes.md         my lab log, Steps 1 to 13, including mistakes and decisions
└── results/
    └── summary.md       baseline counts, scores, and remaining failures
```

The raw OpenSCAP XML and HTML reports are not published because they contain host details.

## Lab setup

- Proxmox VE host with the lab VM on an isolated bridge. NAT gives it outbound internet, and traffic to my home network is dropped.
- Ubuntu 24.04 (Noble) cloud image, 2 vCPUs, 2 GB RAM, 20 GB disk, provisioned with cloud-init.
- OpenSCAP 1.3.9 and SCAP Security Guide 0.1.82, profile `xccdf_org.ssgproject.content_profile_stig`.

## Next steps

- Rescan after the `/var/log/audit` permission fix.
- Work through the 36 remaining findings: AIDE file integrity, sudo authentication, the password delay after a failed login, password hashing, the boot loader password, remote logging, chrony time sync, and the audit "immutable" rule last.
- Write up (not fix) the smart-card, FIPS mode and remote audit server rules as accepted risk for a home lab.
- Add a short write-up of what changed between scans.

## Disclaimer

This is a personal home lab for learning. It is not an official DISA or vendor product, it is not tied to any employer, and it is not a guide for production systems. Test any change on a snapshot first.
