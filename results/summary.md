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

## After six fixes

- oscap score: **60.03%**

I only kept the headline score for this scan, so the per-rule counts are not listed here yet. They will be added with the next full rescan.

## Rules addressed by the six fixes

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

Rule IDs are shown without the `xccdf_org.ssgproject.content_rule_` prefix.

## Remaining baseline failures, by area

These are the other failures from the baseline scan, grouped to plan the next fixes.

- **File integrity (AIDE):** `package_aide_installed`, `aide_build_database`, `aide_check_audit_tools`, `aide_disable_silentreports`, `aide_periodic_cron_checking`
- **FIPS and crypto:** `is_fips_mode_enabled`, `sshd_use_approved_ciphers_ordered_stig`, `sshd_use_approved_kex_ordered_stig`, `sshd_use_approved_macs_ordered_stig`
- **sudo:** `sudo_remove_nopasswd`, `sudo_require_authentication`
- **Passwords and lockout:** `package_pam_pwquality_installed`, `accounts_passwords_pam_faildelay_delay`, `accounts_passwords_pam_faillock_audit`, `accounts_passwords_pam_faillock_interval`, `accounts_passwords_pam_faillock_silent`, `accounts_passwords_pam_faillock_unlock_time`, `set_password_hashing_algorithm_auth_stig`, `accounts_password_pam_unix_rounds_password_auth`, `accounts_maximum_age_login_defs`, `accounts_minimum_age_login_defs`, `account_disable_post_pw_expiration`, `no_empty_passwords`
- **Sessions:** `vlock_installed`, `accounts_max_concurrent_login_sessions`, `accounts_umask_etc_login_defs`
- **Smart card and MFA:** `package_opensc_installed`, `install_smartcard_packages`, `smartcard_configure_ca`, `smartcard_configure_cert_checking`, `smartcard_configure_crl`, `smartcard_pam_enabled`, `package_nss_sss_installed`, `package_pam_sss_installed`
- **SSH daemon:** `sshd_set_keepalive`, `sshd_set_idle_timeout`, `sshd_disable_empty_passwords`, `sshd_disable_x11_forwarding`, `sshd_do_not_permit_user_env`, `sshd_enable_pubkey_auth`, `sshd_x11_use_localhost`
- **Boot loader:** `grub2_password`, `grub2_uefi_password`, `grub2_audit_argument`
- **Firewall:** `check_ufw_active`, `ufw_rate_limit`
- **Logging and audit:** `rsyslog_remote_access_monitoring`, `dir_permissions_system_journal`, `file_permissions_journalctl`, `file_permissions_var_log_stig`, `package_audit-audispd-plugins_installed`
- **Kernel:** `sysctl_net_ipv4_tcp_syncookies`, `sysctl_kernel_dmesg_restrict`, `sysctl_kernel_randomize_va_space`, `kernel_module_usb-storage_disabled`
- **Time sync:** `package_chrony_installed`, `package_timesyncd_removed`
- **Packages:** `clean_components_post_updating`

Not checked at baseline (need a manual review): `account_temp_expire_date`, `ensure_sudo_group_restricted`, `ufw_only_required_services`, `only_allow_dod_certs`.
