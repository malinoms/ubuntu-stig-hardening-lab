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
| Nov 11, about 9:25 PM | 35 failed (pass count not recorded) | not recorded |
| Nov 11, after Fixes 24 to 26 | 188 passed, 26 failed | 79.15% |
| Nov 11, after Fix 27 and a reboot | 198 passed, 23 failed | 85.87% |
| Nov 11, about 9:48 PM, after Fix 28 | 21 failed (pass count not recorded) | 86.43% |
| Nov 12, after Fix 29 | not recorded | 87.22% |
| Nov 12, final (`results-nov12b`), after Fix 30 | 18 failed (pass count not recorded) | 91.59% |

The oscap score went from **51.38% to 91.59%** across thirty fixes, and the work is still in progress. The baseline pass rate and the oscap score are measured differently, and I only kept the pass rate for the baseline. A November 11 rescan around 9:25 PM Mountain confirmed that the `/var/log/audit` permission fix from Fix 23 had taken (35 rules failing, down from 36). I did not record the pass count or the weighted score for that first November 11 scan. November 11 ended at **86.43%** (raw score 86.428566, 21 rules failed). I did not capture the exact pass count for that scan, so I do not claim one. On November 12 the score moved from 86.43% to **87.22%** after Fix 29, then to **91.59%** on the final scan (`results-nov12b`, 18 rules failed). I did not capture the pass count for either November 12 scan. Details are in [results/summary.md](results/summary.md).

## The thirty fixes

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
| 24 | Password delay, hashing, no empty passwords, and disable accounts after the password expires | `account_disable_post_pw_expiration`, `accounts_passwords_pam_faildelay_delay`, `no_empty_passwords`, `accounts_password_pam_unix_rounds_password_auth`, `set_password_hashing_algorithm_auth_stig` |
| 25 | Clean unused packages after updates | `clean_components_post_updating` |
| 26 | Point chrony at reachable time servers, with maxpoll 16 | `chronyd_server_directive`, `chronyd_or_ntpd_set_maxpoll`, `chronyd_sync_clock` |
| 27 | Install remaining packages, tighten log and library permissions, set up AIDE, and turn on audit at boot | `package_audit-audispd-plugins_installed`, `package_nss_sss_installed`, `package_pam_sss_installed`, `dir_permissions_system_journal`, `file_permissions_var_log_stig`, `root_permissions_syslibrary_files`, `aide_check_audit_tools`, `aide_disable_silentreports`, `aide_build_database`, `grub2_audit_argument` |
| 28 | Re-apply log file permissions after reboot, and log sudo use | `file_permissions_var_log_stig`, `audit_sudo_log_events` |
| 29 | Remove the cloud-init NOPASSWD grant so sudo asks for a password | `sudo_remove_nopasswd`, `sudo_require_authentication` |
| 30 | Set a boot loader password, and allow normal boots without a prompt | `grub2_password`, `grub2_uefi_password` |

## Method

For each finding:

1. Take a Proxmox snapshot of the VM before changing anything.
2. Check the current state by hand so I understand the finding.
3. Fix only that rule: `sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --rule <rule-id> ssg-ubuntu2404-ds.xml`
4. Verify the change by hand, then rescan the single rule to confirm it passes.
5. After a batch of fixes, run a full profile scan. In later sessions I also applied a small group of related, low-risk rules in one `--remediate` command, still testing a fresh login and `sudo -v` in a second window before I closed the first.

## Key decisions

The commands are the easy part. These are the calls that mattered.

**Snapshot before every change, and keep a console path.** Any hardening change can break access or leave the system in a state I don't understand. I could fix forward when something broke, or make every change reversible. I took a Proxmox snapshot before each fix and kept the VM console available as a way in that doesn't depend on SSH. When a change did lock me out, the console got me back in and the snapshots gave me a clean place to return to.

**Remediate one rule at a time.** I could apply the whole STIG profile at once or fix one rule at a time. Early on, `oscap xccdf generate fix --rule` ignored `--rule` and wrote about 30,000 lines for the entire profile, and running it enabled the firewall without an SSH rule and locked me out. I rolled back to a clean snapshot instead of keeping a server full of undocumented changes, then switched to `oscap xccdf eval --remediate --rule`, which respects the filter, and I now run `wc -l` on any generated script before I run it.

**Look up rule IDs instead of guessing.** A guessed rule name returned "not found" and wasted a step. I search the datastream for the real IDs instead: `grep -o 'content_rule_[a-z_]*audit[a-z_]*' ssg-ubuntu2404-ds.xml | sort -u`. It takes seconds and removes the guesswork.

**Document the faillock recovery instead of testing a live lockout.** After setting accounts to lock after 3 failed passwords, I could prove it with a real lockout or verify the configuration. A live test would lock `sudo` on my admin account. I verified the `faillock.conf` and PAM lines, and I documented the recovery command (`sudo faillock --user <user> --reset` from the VM console), accepting slightly less proof for much less risk.

**Verify every change by hand.** "No error" doesn't mean a change worked, so I check the actual system state after each fix and rescan the rule. For TMOUT, the old window still showed it blank, and only a new session showed `600`, because login settings apply to new sessions. I treat tool output and AI suggestions as inputs to check: an assistant's guesses on a rule name and on the timeout value were both wrong, and verifying against the system caught both.

**Report the scores honestly.** OpenSCAP reports a weighted score, and the simple pass rate is a different number. The baseline was a 45% pass rate (54 of 119 applicable rules) but a 51.38% weighted score, and the latest scan scored 91.59% weighted (18 rules failed). I did not capture the exact pass count for that scan, so I do not claim one. I report the weighted scores side by side: 51.38% on the baseline, 86.43% at the end of November 11, 87.22% after Fix 29, and 91.59% at the end of November 12. Quoting 45% to 91.59% would compare two different measures. I didn't record per-rule counts for the scans before November 2, so I don't claim any. For the first November 11 rescan I recorded only the fail count (35 rules), not the pass count. For the November 12 midpoint I recorded only the score (87.22%). The score also does not rise one-for-one with rules passed: 59 more rules passing moved it only 3.4 points. After Fix 27, 10 more rules passed but only 3 fewer failed, because installing the SSSD packages made 7 previously not-applicable rules start to apply.

**Isolate the lab network from the home LAN.** The lab VMs needed internet for patches and tools, but I didn't want them reaching my home network. I chose NAT over copying files in by hand, allowed outbound traffic only, added an explicit rule dropping lab traffic to my home LAN, and keep deliberately vulnerable practice VMs powered off while NAT is on. That gave me patching without giving up segmentation.

**Things that surprised me on November 3.** Files in `/etc/audit/rules.d/` must be `0600`; `0640` made an earlier rule fail again. The extended-attribute audit rules need one line for regular users and a second for root. With `UMASK 077`, scan reports created by root are root-only, so I `chown` them before copying them off the VM. The scanner wants the exact, ordered SSH encryption lists from the STIG fix script, not the text in the rule description. And one fix (`log_group = root`) quietly broke a rule that already passed, which I only caught by comparing two scans rule by rule. I save the audit "immutable" rule (`-e 2`) for last, because it locks the audit rules until the next reboot.

**Things that surprised me on November 11.** The STIG time-server name did not resolve from the home network. Pointing chrony at that server and commenting out the working pool lines left the clock with no source. I switched to public NIST servers, confirmed the clock was actually in sync (`^*` in `chronyc sources`), and wrote up the `.mil` server rule as an accepted exception. The lesson: verify a fix actually works, not just that the scanner would pass. Installing the SSSD packages made 7 new rules apply, so the fail count dropped less than the pass count rose. And `/var/log` permission fixes can fail again after a reboot, when the system creates new log files.

**Things that surprised me on November 12.** The first GRUB password attempt left the literal word HASH in the config, so both boot loader rules failed even though the file looked finished. The hash I pasted landed on its own line. The scanner reads `/boot/grub/grub.cfg`, so that is the file to check after `update-grub`. Neither GRUB password rule has an automatic fix. Once sudo asks for a password, checks and scripts that used passwordless sudo stop working. And the `/var/log` permission rule failed again after the reboot that confirmed the boot loader change.

## Repo layout

```
.
├── README.md            this overview
├── runbook.md           step-by-step commands and checks for Fixes 1 to 30
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

The lab is still in progress. "Done" means every remaining rule either passes or is written up as an accepted exception with a reason.

- Next session: remote logging and audit offload (`rsyslog_remote_access_monitoring`, `auditd_audispd_configure_remote_server`, `auditd_offload_logs`). These need a central log server. A small container on the lab host is one option.
- Re-apply `file_permissions_var_log_stig`. It passed after Fix 28 and failed again after the November 12 reboot, because some log files came back with looser permissions.
- Last of the real fixes: the audit "immutable" rule (`audit_rules_immutable`). It locks the audit rules until the next reboot.
- Write up the 13 planned exceptions: the 5 remaining smart-card rules, the 6 SSSD rules (SSSD is the service that links logins to a smart card or a company directory, which a standalone home lab does not have), FIPS mode, and the military time-server rule (`chronyd_specify_remote_server`). The scanner only accepts one exact `.mil` time server, which did not resolve from this home network.
- Automate the confirmed fixes with Ansible. sudo now requires a password, so that automation cannot rely on passwordless sudo.

## Disclaimer

This is a personal home lab for learning. It is not an official DISA or vendor product, it is not tied to any employer, and it is not a guide for production systems. Test any change on a snapshot first.
