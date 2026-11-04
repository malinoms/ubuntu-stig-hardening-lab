# Scan Results Summary

All scans used OpenSCAP 1.3.9 with SCAP Security Guide 0.1.82 (`ssg-ubuntu2404-ds.xml`) and the profile `xccdf_org.ssgproject.content_profile_stig` (DISA STIG for Ubuntu 24.04).

The raw XML and HTML reports are not published here because they contain host details such as addresses and hostnames.

## Two ways to read the score

- **Pass rate:** rules that passed, divided by rules that apply to this server (pass plus fail).
- **oscap score:** the weighted score oscap writes into the results file (`urn:xccdf:scoring:default`, out of 100). This is the number shown at the top of the HTML report.

## Baseline (stock, fully patched Ubuntu 24.04 cloud image)

| Result | Rules |
|---|---|
| pass | 54 |
| fail | 65 |
| not applicable | 116 |
| not checked | 4 |
| error | 0 |
| **Total evaluated** | **239** |

- Pass rate: 54 of 119 applicable rules, about **45%**
- oscap score: **51.38%**

## Score history

| After | oscap score | Notes |
|---|---|---|
| Baseline | 51.38% | 54 pass, 65 fail (45% pass rate) |
| Fix 6 | 60.03% | Fixes 1 to 6 |
| Fix 10 | 61.22% | Fixes 7 to 10 |
| Fix 11 | 62.02% | sudo now asks for a password |
| Fix 16 | 68.60% | Fixes 12 to 16 (raw score 68.596458) |
| Nov 2, full scan | 68.73% | 96 pass |
| Nov 2, later scan | 67.95% | 97 pass. The score went down slightly while one more rule passed; I did not compare the two reports rule by rule |
| Nov 3, about 5:07 PM | 68.74% | 98 pass, 116 fail. Fixes 17 and 18 (every SSH rule passes) |
| Nov 3, about 5:34 PM | 72.15% | 157 pass, 57 fail. Fixes 19 to 21 (59 audit rules) |
| Nov 3, about 5:54 PM | 75.3% | 178 pass, 36 fail. Fixes 22 and 23. 23 rules newly pass, 1 regressed (`directory_permissions_var_log_audit`) |

I only kept the headline score for the scans between the baseline and November 2, so per-rule counts for those scans are not listed here. From November 2 on I kept the counts. The table compares the weighted oscap score throughout. The score does not rise one-for-one with rules passed: going from 98 to 157 passed rules moved it 3.4 points. The `/var/log/audit` permission fix was made after the 5:54 PM scan and has not been rescanned yet.

Scan commands, and a lesson from the Fix 16 rescan: the content file was in my home folder (`~/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml`), not under `/usr/share`. My first command sent all output to `/dev/null`, so the wrong path only showed up as a missing results file. Discard stdout only, so errors stay visible.

## Rules addressed by each fix

"Baseline result" is what the baseline failure list showed for the rule.

| Fix | Rule ID | Baseline result |
|---|---|---|
| 1 | `banner_etc_issue_net` | fail |
| 1 | `sshd_enable_warning_banner_net` | fail |
| 2 | `banner_etc_profiled_ssh_confirm` | fail |
| 3 | `disable_ctrlaltdel_reboot` | fail |
| 4 | `accounts_passwords_pam_faillock_deny` | fail |
| 5 | `accounts_tmout` | fail |
| 6 | `package_audit_installed` | fail |
| 6 | `service_auditd_enabled` | not applicable (auditd was not installed yet) |
| 7 | `file_permissions_etc_audit_rulesd` | not in the baseline failure list |
| 8 | `package_pam_pwquality_installed` | fail |
| 9 | `vlock_installed` | fail |
| 10 | `package_opensc_installed` | fail |
| 11 | `sudo_remove_nopasswd` | fail |
| 12 | `sshd_set_keepalive` | fail |
| 12 | `sshd_set_idle_timeout` | fail |
| 12 | `sshd_disable_empty_passwords` | fail |
| 12 | `sshd_disable_x11_forwarding` | fail |
| 12 | `sshd_x11_use_localhost` | fail |
| 12 | `sshd_do_not_permit_user_env` | fail |
| 12 | `sshd_enable_pubkey_auth` | fail |
| 13 | `sysctl_net_ipv4_tcp_syncookies` | fail |
| 13 | `sysctl_kernel_dmesg_restrict` | fail |
| 13 | `sysctl_kernel_randomize_va_space` | fail |
| 13 | `kernel_module_usb-storage_disabled` | fail |
| 14 | `check_ufw_active` | fail |
| 14 | `ufw_rate_limit` | fail |
| 15 | `package_chrony_installed` | fail |
| 15 | `package_timesyncd_removed` | fail |
| 16 | `dir_permissions_system_journal` | fail |
| 16 | `file_permissions_journalctl` | fail |
| 16 | `file_permissions_var_log_stig` | fail |

Rule IDs are shown without the `xccdf_org.ssgproject.content_rule_` prefix. I applied these fixes to target these rules. I did not record per-rule results from the later rescans, only the overall score.

## Still failing after the 75.3% scan (36 rules)

- **File integrity (AIDE):** build the database, protect the audit tools, turn off silent reports
- **FIPS mode** (a U.S. government encryption standard)
- **sudo:** the "NOPASSWD" and "require authentication" rules
- **Updates:** clean up old components after updating
- **Passwords:** a delay after a failed login (faildelay), password hashing and rounds, no empty passwords, disable accounts after the password expires
- **Smart card login:** 7 rules, probably documented as accepted risk on a home lab
- **Boot loader:** a grub2 password, and the audit setting on the boot line
- **Logging:** rsyslog remote monitoring, journal folder permissions, `/var/log` file permissions, system library ownership
- **Time sync (chrony):** 4 rules
- **Audit, last:** the immutable rule, sudo log events, and a remote audit server with log offload

The `directory_permissions_var_log_audit` regression has been fixed (`chmod 0700 /var/log/audit`) but not rescanned.
