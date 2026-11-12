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
| Nov 11, about 9:25 PM | not recorded | 35 fail. Confirmed the Fix 23 `/var/log/audit` permission change. Pass count and weighted score were not recorded |
| Nov 11, after Fixes 24 to 26 | 79.15% | 188 pass, 26 fail (raw score 79.151375). Password, package-cleanup and chrony time-sync rules. `chronyd_specify_remote_server` still failed, by design |
| Nov 11, after Fix 27 and a reboot | 85.87% | 198 pass, 23 fail (raw score 85.873016). 10 more rules passed, but only 3 fewer failed: not-applicable dropped from 20 to 13 after the SSSD packages were installed |
| Nov 11, about 9:48 PM, after Fix 28 | 86.43% | 21 fail (raw score 86.428566). Pass count was not recorded |

I only kept the headline score for the scans between the baseline and November 2, so per-rule counts for those scans are not listed here. From November 2 on I kept the counts, except for two November 11 scans: the 9:25 PM rescan (fail count only) and the final 9:48 PM scan (score and fail count only). The table compares the weighted oscap score throughout. The score does not rise one-for-one with rules passed: going from 98 to 157 passed rules moved it 3.4 points. Installing packages can also make previously not-applicable rules start to apply, so the fail count can drop less than the pass count rises.

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
| 24 | `account_disable_post_pw_expiration` | fail |
| 24 | `accounts_passwords_pam_faildelay_delay` | fail |
| 24 | `no_empty_passwords` | fail |
| 24 | `accounts_password_pam_unix_rounds_password_auth` | fail |
| 24 | `set_password_hashing_algorithm_auth_stig` | fail |
| 25 | `clean_components_post_updating` | fail |
| 26 | `chronyd_server_directive` | fail |
| 26 | `chronyd_or_ntpd_set_maxpoll` | fail |
| 26 | `chronyd_sync_clock` | fail |
| 27 | `package_audit-audispd-plugins_installed` | fail |
| 27 | `package_nss_sss_installed` | fail |
| 27 | `package_pam_sss_installed` | fail |
| 27 | `dir_permissions_system_journal` | fail (had failed again after Fix 16) |
| 27 | `file_permissions_var_log_stig` | fail (had failed again after Fix 16) |
| 27 | `root_permissions_syslibrary_files` | fail |
| 27 | `aide_check_audit_tools` | fail |
| 27 | `aide_disable_silentreports` | fail |
| 27 | `aide_build_database` | fail |
| 27 | `grub2_audit_argument` | fail |
| 28 | `file_permissions_var_log_stig` | fail (regressed after the Fix 27 reboot when new logs were created) |
| 28 | `audit_sudo_log_events` | fail |

Rule IDs are shown without the `xccdf_org.ssgproject.content_rule_` prefix. I applied these fixes to target these rules. I did not record per-rule results from the later rescans, only the overall score. Fixes 17 to 23 are listed in the README and the runbook; I did not add them to this table at the time.

## Still failing after the 86.43% scan (21 rules)

"Done" for this lab means every remaining rule either passes or is written up as an accepted exception with a reason.

**Planned exceptions (13 rules).** These are an honest call for a standalone home lab, not a shortcut:

- **Smart card login:** `install_smartcard_packages`, `smartcard_configure_ca`, `smartcard_configure_cert_checking`, `smartcard_configure_crl`, `smartcard_pam_enabled`
- **SSSD** (the service that links logins to a smart card or a company directory, which this lab does not have): `service_sssd_enabled`, `sssd_certification_path_trust_anchor`, `sssd_enable_pam_services`, `sssd_enable_smartcards`, `sssd_enable_user_cert`, `sssd_offline_cred_expiration`
- **FIPS mode:** `is_fips_mode_enabled` (a U.S. government encryption standard)
- **Military time server:** `chronyd_specify_remote_server`. The scanner only accepts the exact server `0.us.pool.ntp.mil`, which did not resolve from this home network. Chrony is synced to public NIST servers instead (see Fix 26).

**Real fixes still to do (8 rules):**

- **Boot loader password** (next session, lockout risk): `grub2_password`, `grub2_uefi_password`
- **sudo authentication** (next session, lockout risk): `sudo_remove_nopasswd`, `sudo_require_authentication`
- **Remote logging and audit offload** (need a log receiver, possibly a small container): `rsyslog_remote_access_monitoring`, `auditd_audispd_configure_remote_server`, `auditd_offload_logs`
- **Audit, last:** `audit_rules_immutable`

After those, the confirmed fixes can be automated with Ansible.
