# Ubuntu 24.04 STIG Hardening Lab

I took a fresh Ubuntu 24.04 server and hardened it against the DISA STIG using OpenSCAP and the SCAP Security Guide (ComplianceAsCode) 0.1.82, one rule at a time, in my Proxmox home lab. The goal was to learn what each control does and to make each change deliberately: weigh the risk, keep a way back, and verify the result, not just raise a number. This repo holds the runbook I wrote as I went, my lab notes (including the mistakes), and a summary of the scan results.

## Results

| Scan | Pass rate (applicable rules) | oscap score |
|---|---|---|
| Baseline, stock patched server | 45% (54 of 119) | 51.38% |
| After six fixes | not recorded | 60.03% |

The baseline pass rate and the oscap score are measured differently. Details are in [results/summary.md](results/summary.md).

## The six fixes

Rule IDs are shown without the `xccdf_org.ssgproject.content_rule_` prefix.

| Fix | What it does | Rule IDs |
|---|---|---|
| 1 | DoD notice-and-consent banner before SSH login | `banner_etc_issue_net`, `sshd_enable_warning_banner_net` |
| 2 | Login confirmation prompt that ends the session unless the user agrees | `banner_etc_profiled_ssh_confirm` |
| 3 | Disable the Ctrl+Alt+Del reboot | `disable_ctrlaltdel_reboot` |
| 4 | Lock accounts after 3 failed password attempts | `accounts_passwords_pam_faillock_deny` |
| 5 | Log out idle shells after 10 minutes (TMOUT=600) | `accounts_tmout` |
| 6 | Install and enable the audit system | `package_audit_installed`, `service_auditd_enabled` |

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

**Report the scores honestly.** OpenSCAP reports a weighted score, and the simple pass rate is a different number. The baseline was a 45% pass rate (54 of 119 applicable rules) but a 51.38% weighted score, and the scan after six fixes scored 60.03% weighted. I report the weighted scores side by side rather than quoting 45% to 60%, which would compare two different measures.

**Isolate the lab network from the home LAN.** The lab VMs needed internet for patches and tools, but I didn't want them reaching my home network. I chose NAT over copying files in by hand, allowed outbound traffic only, added an explicit rule dropping lab traffic to my home LAN, and keep deliberately vulnerable practice VMs powered off while NAT is on. That gave me patching without giving up segmentation.

## Repo layout

```
.
├── README.md            this overview
├── runbook.md           step-by-step commands and checks for each fix
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

- Work through more findings: AIDE file integrity, sudo NOPASSWD, password quality, SSH daemon settings, and the remaining faillock options.
- Run a final full rescan and publish the pass and fail counts alongside the score.
- Add the rescan summary and a short write-up of what changed between scans.

## Disclaimer

This is a personal home lab for learning. It is not an official DISA or vendor product, it is not tied to any employer, and it is not a guide for production systems. Test any change on a snapshot first.
