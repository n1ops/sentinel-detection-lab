# Sentinel Detection Lab -- Comprehensive Security Audit Report

**Date:** 2026-03-02
**Repository:** `n1ops/sentinel-detection-lab`
**Auditor:** Claude Opus 4.6 (6 parallel agent teams)
**Scope:** Full project -- Terraform, GitHub Actions, KQL detections, ARM templates, Python scripts, workbooks, git config

---

## Executive Summary

Six specialized agent teams performed a comprehensive security audit of the `sentinel-detection-lab` project, analyzing every file across all technology layers. The project demonstrates **strong foundational security practices** -- no hardcoded secrets, consistent MITRE ATT&CK alignment, well-structured Terraform with DRY patterns, and proper managed identity usage. However, several critical and high-severity findings require immediate remediation.

### Findings Summary

| Severity | Count | Key Areas |
|----------|-------|-----------|
| **CRITICAL** | 4 | Terraform local state, unpinned GH Actions, PowerShell evasion bypass, KQL logic bug |
| **HIGH** | 15 | Supply chain risks, blanket secret inheritance, missing OIDC, placeholder domains, detection evasion |
| **MEDIUM** | 21 | Version constraints, missing permissions, log gaps, playbook issues, detection completeness |
| **LOW** | 18 | Variable validation, encoding handling, case sensitivity, documentation |
| **INFO** | 10 | Positive findings and informational notes |
| **TOTAL** | **68** | |

### Overall Scores by Area

| Area | Score | Grade |
|------|-------|-------|
| Terraform IaC | 7/10 | B |
| GitHub Actions CI/CD | 5/10 | C |
| KQL Detection Rules | 7/10 | B |
| ARM Templates / Playbooks | 6/10 | C+ |
| Git Configuration | 7/10 | B |
| Python Scripts | 8/10 | B+ |

---

## P0 -- CRITICAL FINDINGS (Fix Immediately)

### 1. Terraform State Stored Locally (CRITICAL)
**File:** `terraform/main.tf`
- No remote backend configured. State files contain sensitive resource IDs and outputs
- State is unencrypted, unversioned, and has no locking or access control
- **Fix:** Configure Azure Storage backend with encryption and RBAC

### 2. All GitHub Actions Unpinned -- Supply Chain Risk (CRITICAL)
**Files:** `.github/workflows/security.yml`, `.github/workflows/sentinel-validate.yml`
- All 6 action references use mutable tags (`@v4`, `@v5`, `@v2`, `@v3`) instead of SHA hashes
- Reusable workflow pinned to `@main` -- mutable branch reference with `secrets: inherit`
- Direct exposure to attacks like tj-actions/changed-files (CVE-2025-30066)
- **Fix:** Pin all actions and workflows to full commit SHA hashes

### 3. Password Spray Detection -- SuccessCount Always Zero (CRITICAL)
**File:** `detections/credential-access/password-spray.kql`
- Query filters to failed sign-ins only, then tries to `countif(ResultType == "0")` -- always returns 0
- Misleading metric that conceals whether spray attacks succeeded
- **Fix:** Use two-stage query or remove contradictory countif

### 4. Encoded PowerShell Detection -- Trivially Bypassable (CRITICAL)
**File:** `detections/defense-evasion/encoded-powershell.kql`
- Easily bypassed via caret insertion, renamed binaries, .NET automation, IEX with encoding classes
- **Fix:** Add obfuscation-aware patterns, parent-child process correlation

---

## P1 -- HIGH FINDINGS (Fix This Sprint)

### GitHub Actions / CI/CD
5. **Reusable workflow `@main` + `secrets: inherit`** -- full secret exposure if devsecops-pipeline-reference is compromised
6. **No `permissions:` block on either workflow** -- defaults to overly broad read-write GITHUB_TOKEN
7. **Azure credentials stored as static secret** -- long-lived service principal JSON blob instead of OIDC
8. **Blanket `secrets: inherit`** -- passes ALL secrets to external reusable workflow

### KQL Detections
9. **Placeholder `yourdomain.com` in 2 rules** -- if deployed, ALL forwarding treated as external (massive FPs or blind spot)
10. **Password spray groups by IP only** -- distributed sprays from rotating IPs completely evade detection
11. **Phishing inbox rule -- hardcoded folder names** -- attackers use custom folders to evade
12. **OAuth consent -- hardcoded array index `[4]`** -- schema changes cause silent detection failure

### Terraform
13. **CMK encryption explicitly disabled** on Sentinel workspace
14. **`.terraform.lock.hcl` excluded from git** -- undermines provider integrity verification

### ARM / Git Config
15. **Teams parameters not wired in playbook** -- `TeamsChannelId`/`TeamsGroupId` never referenced, playbook fails at runtime
16. **Missing `*.tfvars` from `.gitignore`** -- risk of accidental credential commits
17. **`.tfstate` allowlisted in gitleaks** -- weakens secret detection if state accidentally committed

---

## P2 -- MEDIUM FINDINGS (Fix This Month)

### Terraform
18. Provider version constraint `~> 4.0` too permissive (pin to `~> 4.62.0`)
19. Terraform core version `>= 1.5.0` allows old CVE-affected versions (use `>= 1.9.0, < 2.0.0`)
20. Log retention at 31 days -- below NIST/CIS recommendation of 90+ days
21. Subscription ID exposed in outputs without `sensitive = true`
22. Missing diagnostic log categories (ServiceHealth, ResourceHealth)
23. Auto-close automation rule falsely classifies informational incidents as BenignPositive
24. No network restrictions on Log Analytics workspace (public internet accessible)

### GitHub Actions
25. `continue-on-error: true` on Azure login masks authentication failures silently
26. Shell injection risk in ARM validation step via `find` output interpolation
27. No concurrency controls -- parallel runs waste minutes and risk race conditions
28. No `timeout-minutes` -- default 6-hour timeout on all jobs

### KQL Detections
29. Missing Conditional Access status in credential-access rules
30. Missing Risk Level/Risk State in all SigninLogs-based rules
31. Impossible travel `serialize`/`prev()` pattern expensive on large tenants
32. 14-day RDP baseline `materialize()` cost -- re-scans 14 days every hour
33. Bulk file download `RecordType` string/int mismatch across environments
34. Missing `Entity_IP` in multi-host admin logon detection
35. Service principal detection has no allow-list (noisy in DevOps environments)

### ARM Template
36. No trigger conditions -- phishing playbook fires on ALL incidents
37. No error handling scopes in Logic App workflow
38. HTML injection risk in Teams message body from incident data

---

## P3 -- LOW FINDINGS (Backlog)

### Terraform
39. Variables `location` and `resource_prefix` missing validation blocks
40. Alert rule suppression disabled globally (alert fatigue risk)
41. No `lifecycle { prevent_destroy = true }` on critical resources
42. Provider authentication method not explicit

### KQL Detections
43. Brute force threshold of 10 too low for cloud environments
44. No brute force success-after-failure correlation
45. Case-sensitive `!in` in multi-host admin (should be `!in~`)
46. Impossible travel MITRE mapping inconsistent with directory placement
47. No alert deduplication logic across detection rules

### ARM / Git / Python
48. No `minLength`/`allowedPattern` on ARM template parameters
49. Missing `.claude/` directory from `.gitignore`
50. No custom Azure-specific gitleaks rules
51. Python script lacks symlink protection, file size limits, encoding error handling
52. Workbook `fallbackResourceIds` contains placeholder tokens
53. Missing security documentation section in README

---

## MITRE ATT&CK Coverage Analysis

### Current Coverage (6 of 12 tactics)
```
[COVERED]    Initial Access ......... T1566.001, T1566.002 (2 rules)
[NONE]       Execution .............. 0 rules
[COVERED]    Persistence ............ T1137.005, T1136.003 (2 rules)
[NONE]       Privilege Escalation ... 0 rules
[COVERED]    Defense Evasion ........ T1027 (1 rule)
[COVERED]    Credential Access ...... T1110.001, T1110.003, T1078 (3 rules)
[NONE]       Discovery .............. 0 rules
[COVERED]    Lateral Movement ....... T1021.001, T1078.002 (2 rules)
[NONE]       Collection ............. 0 rules
[COVERED]    Exfiltration ........... T1567, T1114.003 (2 rules)
[NONE]       Command & Control ...... 0 rules
[NONE]       Impact ................. 0 rules
```

### Recommended Additional Detections (10)
1. **T1053.005** -- Suspicious Scheduled Task Creation (Execution/Persistence)
2. **T1562.001** -- Conditional Access Policy Modification (Defense Evasion)
3. **T1621** -- MFA Fatigue / Push Spam Detection (Credential Access)
4. **T1578** -- Suspicious Azure Resource Deployment (Impact)
5. **T1555** -- Azure Key Vault Secrets Access Anomaly (Credential Access)
6. **T1486** -- Ransomware Mass File Encryption (Impact)
7. **T1098.003** -- Privileged Azure AD Role Assignment (Privilege Escalation)
8. **T1055** -- Suspicious Process Injection via Windows Events (Defense Evasion)
9. **T1090.003** -- Sign-In from TOR/Anonymizer Network (C2)
10. **T1048.003** -- Large Email Attachment Exfiltration (Exfiltration)

---

## Positive Findings (What's Done Well)

1. **Zero hardcoded secrets** across all Terraform, ARM, and script files
2. **Consistent MITRE ATT&CK mapping** on all 12 detection rules
3. **Standardized entity columns** (Entity_Account, Entity_IP, Entity_Host) in 11/12 rules
4. **Excellent KQL code quality** -- consistent `let` statements, time filters early, clear comments
5. **DRY Terraform patterns** -- `for_each` with locals map for analytics rules
6. **Proper managed identity** on Sentinel connection in playbook
7. **Sensitive files excluded** in `.gitignore` (.env, *.pem, *.key, credentials.json, *.tfstate)
8. **Safe workflow triggers** -- no `pull_request_target`, proper path filters
9. **Consistent tagging** -- Environment, Project, ManagedBy on all resources
10. **Workbook parameters** properly use server-side substitution (no KQL injection)

---

## Prioritized Remediation Roadmap

### Week 1 (Critical)
| # | Action | Effort | Files |
|---|--------|--------|-------|
| 1 | Pin all GH Actions to SHA hashes | Low | `.github/workflows/*.yml` |
| 2 | Add `permissions: contents: read` to workflows | Low | `.github/workflows/*.yml` |
| 3 | Add `*.tfvars` to `.gitignore` | Low | `.gitignore` |
| 4 | Fix password spray SuccessCount logic | Low | `detections/credential-access/password-spray.kql` |
| 5 | Replace placeholder `yourdomain.com` with Watchlist | Low | 2 KQL files |
| 6 | Wire Teams parameters in playbook | Medium | `playbooks/phishing-response/azuredeploy.json` |

### Week 2 (High)
| # | Action | Effort | Files |
|---|--------|--------|-------|
| 7 | Migrate Azure auth to OIDC | Medium | Workflow + Entra ID config |
| 8 | Replace `secrets: inherit` with explicit secrets | Low | `security.yml` |
| 9 | Configure remote Terraform backend | Medium | `terraform/main.tf` |
| 10 | Commit `.terraform.lock.hcl` | Low | `.gitignore` |
| 11 | Pin provider version to `~> 4.62.0` | Low | `terraform/main.tf` |
| 12 | Remove `.tfstate` from gitleaks allowlist | Low | `.gitleaks.toml` |

### Week 3 (Medium)
| # | Action | Effort | Files |
|---|--------|--------|-------|
| 13 | Add PowerShell evasion-resistant patterns | Medium | `detections/defense-evasion/encoded-powershell.kql` |
| 14 | Add complementary distributed spray detection | Medium | New KQL file |
| 15 | Fix OAuth hardcoded array index | Low | `detections/initial-access/suspicious-oauth-consent.kql` |
| 16 | Add concurrency + timeout to workflows | Low | `.github/workflows/*.yml` |
| 17 | Add Dependabot for actions | Low | `.github/dependabot.yml` |
| 18 | Add CODEOWNERS file | Low | `.github/CODEOWNERS` |

### Week 4+ (Enhancement)
| # | Action | Effort | Files |
|---|--------|--------|-------|
| 19 | Add 10 recommended detections | High | `detections/` (new files) |
| 20 | Add playbook error handling scopes | Medium | ARM template |
| 21 | Add branch protection rules | Low | GitHub repo settings |
| 22 | Add OpenSSF Scorecard to CI | Low | New workflow |
| 23 | Extend KQL validator with unit tests | Medium | `scripts/` |
| 24 | Add Harden-Runner to workflow jobs | Low | `.github/workflows/*.yml` |

---

## References & Sources

- [StepSecurity - Pinning GitHub Actions](https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide)
- [Wiz - tj-actions Supply Chain Attack Analysis (CVE-2025-30066)](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [GitHub Docs - Security Hardening for Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Microsoft Learn - Sentinel Best Practices](https://learn.microsoft.com/en-us/azure/sentinel/best-practices)
- [Microsoft - Securing Terraform State in Azure](https://techcommunity.microsoft.com/t5/fasttrack-for-azure/securing-terraform-state-in-azure/ba-p/3787254)
- [Spacelift - Terraform Security Best Practices](https://spacelift.io/blog/terraform-security)
- [HashiCorp - Protect Sensitive Variables](https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables)
- [Northwave - Testing Sentinel Analytic Rules at Scale](https://northwave-cybersecurity.com/threat-intel-research/soc-testing-microsoft-sentinel-analytic-rules-at-scale)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [OpenSSF - Securing CI/CD After Supply Chain Attacks](https://openssf.org/blog/2025/06/11/maintainers-guide-securing-ci-cd-pipelines-after-the-tj-actions-and-reviewdog-supply-chain-attacks/)

---

*Generated by 6 parallel Claude Opus 4.6 agent teams on 2026-03-02*
