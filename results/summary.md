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

I only kept the headline score for the scans after the baseline, so per-rule pass and fail counts for those scans are not listed here. The pass rate (45%) is only known for the baseline, so the table compares the weighted oscap score throughout. I plan to add counts with the next full rescan.

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

## Remaining baseline failures, by area

These are the baseline failures that Fixes 1 to 16 did not target, grouped to plan the next fixes. The SSH daemon, firewall, kernel and time sync groups are now fully covered by Fixes 12 to 15. That is based on which rules I targeted, not on a per-rule rescan.

- **File integrity (AIDE):** `package_aide_installed`, `aide_build_database`, `aide_check_audit_tools`, `aide_disable_silentreports`, `aide_periodic_cron_checking`
- **FIPS and crypto:** `is_fips_mode_enabled`, `sshd_use_approved_ciphers_ordered_stig`, `sshd_use_approved_kex_ordered_stig`, `sshd_use_approved_macs_ordered_stig`
- **sudo:** `sudo_require_authentication`
- **Passwords and lockout:** `accounts_passwords_pam_faildelay_delay`, `accounts_passwords_pam_faillock_audit`, `accounts_passwords_pam_faillock_interval`, `accounts_passwords_pam_faillock_silent`, `accounts_passwords_pam_faillock_unlock_time`, `set_password_hashing_algorithm_auth_stig`, `accounts_password_pam_unix_rounds_password_auth`, `accounts_maximum_age_login_defs`, `accounts_minimum_age_login_defs`, `account_disable_post_pw_expiration`, `no_empty_passwords`
- **Sessions:** `accounts_max_concurrent_login_sessions`, `accounts_umask_etc_login_defs`
- **Smart card and MFA** (probably documented as accepted risk instead of fixed on a home lab): `install_smartcard_packages`, `smartcard_configure_ca`, `smartcard_configure_cert_checking`, `smartcard_configure_crl`, `smartcard_pam_enabled`, `package_nss_sss_installed`, `package_pam_sss_installed`
- **Boot loader:** `grub2_password`, `grub2_uefi_password`, `grub2_audit_argument`
- **Logging and audit:** `rsyslog_remote_access_monitoring`, `package_audit-audispd-plugins_installed`
- **Packages:** `clean_components_post_updating`

Not checked at baseline (need a manual review): `account_temp_expire_date`, `ensure_sudo_group_restricted`, `ufw_only_required_services`, `only_allow_dod_certs`.
