# 🧪 How to Build a Threat Detection Use Case — A Practical Checklist

> A 9-step checklist for detection engineers and analysts building their first detection use cases.

---

## Overview

Building a detection use case is more than just writing a query. It requires understanding the technology you're monitoring, knowing what normal looks like, researching existing work, and continuously improving after deployment.

This guide walks through a practical 9-step checklist that covers the full journey from exploratory research all the way to production maintenance.

---

## The Checklist at a Glance
1-Understand the technology and environment 

2-Define normal vs. abnormal behaviour

3-Research existing use cases

4-Collect and validate logs

5-Draft detection logic (Sigma / YARA)

6-Validate in dev/test environment

7-Peer review and stakeholder feedback

8-Deploy to production

9-Maintain and improve continuously

---

## Before You Start — Foundational Reading

If you are new to detection engineering, it is worth grounding yourself in the basics before jumping into use case development. Key concepts to understand upfront:

- **What is Detection Engineering?** — the discipline of translating adversary behavior into operational alerts
- **The Detection Engineering Lifecycle** — creation → testing → deployment → tuning
- **Detection Engineering Maturity Models** — frameworks for measuring how advanced your detection programme is

Useful starting points:
- [Detection Engineering Explained — Splunk](https://www.splunk.com/en_us/blog/learn/detection-engineering.html)
- [Detection Engineering Maturity Matrix — Kyle Bailey](https://detectionengineering.io/)
- [About Detection Engineering — Florian Roth](https://cyb3rops.medium.com/about-detection-engineering-44d39e0755f0)
- [What Makes a "Good" Detection? — Dylan Williams](https://medium.com/@dylanhwilliams/what-makes-a-good-detection-dd6a3b373860)

---

## ① Understand the Technology and Environment

> You cannot detect what you do not understand.

This is the exploratory phase. Your goal is not to write a detection yet — it is to deeply understand the technology you are working with and how it is used in your organisation.

**What to do:**
- Identify the specific technology or service (e.g. AWS IAM Roles Anywhere, Azure AD, a custom internal API)
- Review internal documentation — Confluence, Slack, SharePoint, GitHub/GitLab repos, architecture diagrams
- Understand the deployment context: cloud, on-prem, hybrid, containerised
- Map dependencies: API flows, authentication methods, SSO integrations
- Where possible, access dev or prod environments hands-on to explore the technology directly
- Research related CVEs and check for public proof-of-concept exploits
- Check threat intelligence feeds for any known abuse of the technology

**Example:** If building use cases for AWS IAM Roles Anywhere:
1. Read the [AWS IAM Roles Anywhere User Guide](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
2. Supplement with external research like [Unit 42's analysis](https://unit42.paloaltonetworks.com/aws-roles-anywhere/)
3. Study attacker abuse scenarios — e.g. using Roles Anywhere for persistence

**Useful resources for CVE/exploit research:**
- [cve.org](https://www.cve.org/)
- [trickest/cve on GitHub](https://github.com/trickest/cve)

---

## ② Define Normal vs. Abnormal Behaviour

> Start by understanding what normal looks like — then look for deviations.

Based on your research in Step 1, map out the expected normal flow of the technology. Then identify where an attacker could deviate from that flow.

**What to do:**
- Create a simple flow diagram of how the technology behaves under normal use (a text diagram with arrows is fine)
- Mark points on the diagram where malicious or anomalous behaviour could occur — these are your detection opportunities
- Map those opportunities to [MITRE ATT&CK](https://attack.mitre.org/) tactics and techniques, or to the [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- If you identify multiple potential use cases, document each one separately with its own attack surface and entry points

**Example mapping:**

| Normal Behaviour | Abnormal Behaviour | ATT&CK Technique |
|---|---|---|
| Service account authenticates from known IP | Service account authenticates from foreign IP at 2am | T1078 – Valid Accounts |
| Admin creates scheduled task via approved tooling | Non-admin process creates encoded scheduled task | T1053 – Scheduled Task |
| Single login attempt per session | 100 failed logins across multiple accounts in 5 minutes | T1110 – Brute Force |

---

## ③ Research Existing Use Cases

> Don't reinvent the wheel — leverage open content and community knowledge.

Before writing your own detection logic, check whether something similar already exists. Review it, understand the gaps for your environment, and adapt it.

**Where to look:**

| Source | Link |
|--------|------|
| Microsoft Sentinel community rules | [Azure-Sentinel GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Amazon%20Web%20Services) |
| SigmaHQ rule library | [SigmaHQ GitHub](https://github.com/SigmaHQ/sigma/tree/master/rules) |
| Elastic prebuilt rules | [Elastic Security](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html) |
| Google Chronicle detection rules | [Chronicle GitHub](https://github.com/chronicle/detection-rules/tree/main/rules) |
| Splunk security content | [Splunk GitHub](https://github.com/splunk/security_content/tree/develop/detections) |
| SOC Prime | [socprime.com](https://socprime.com/) |

When you find a similar detection, ask:
- Does it cover my specific technology and data source?
- What are the gaps for my environment?
- Is the logic still current, or is it based on old attacker behaviour?

---

## ④ Collect and Validate Logs

> Use case quality depends on logging quality.

A detection is only as good as the logs it runs on. Before writing logic, confirm the right logs exist, are being ingested, and are correctly parsed.

**What to check:**
- Are logs from the relevant source being collected? (e.g. Windows Security Event logs, Sysmon, Linux audit, cloud provider logs)
- Are logs being ingested into your SIEM with no gaps or delays?
- Are all fields needed for the detection correctly parsed and extracted?
- Do field names match what your detection logic expects?

**Common log sources by use case type:**

| Use Case Area | Log Source |
|---|---|
| Endpoint activity | Windows Event Logs, Sysmon, EDR telemetry |
| Identity and authentication | Azure AD Sign-in logs, Windows Security 4624/4625 |
| Cloud activity | AWS CloudTrail, Azure Activity Logs, GCP Audit Logs |
| Network | Firewall logs, proxy logs, NetFlow, DNS logs |
| Email | Mail gateway logs, O365 MessageTrace |

---

## ⑤ Draft Detection Logic in a Reusable Format

> Write once, deploy anywhere.

Before translating your logic into your SIEM's native query language, write it first in a platform-agnostic format. The recommended approach is **Sigma rules**.

### Why Sigma?

Sigma is a generic signature format for SIEM systems. A single Sigma rule can be compiled into Elasticsearch KQL, Splunk SPL, Microsoft Sentinel KQL, QRadar AQL, and more. It also integrates naturally with Detection-as-Code workflows.

### Sigma Rule Template

```yaml
title: <Short descriptive title>
id: <UUID>
status: experimental
description: <What this detects and why it matters>
references:
    - <links to relevant blog posts, CVEs, ATT&CK pages>
author: <your name or handle>
date: YYYY/MM/DD
tags:
    - attack.<tactic>
    - attack.t<technique_id>
logsource:
    product: <windows / linux / aws / azure / etc>
    service: <security / sysmon / cloudtrail / etc>
detection:
    selection:
        <field_name>: <value>
    condition: selection
falsepositives:
    - <Known benign scenarios that might trigger this>
level: <low / medium / high / critical>
```

**Example — detecting encoded PowerShell:**

```yaml
title: Encoded PowerShell Command Execution
id: a7c3f2e1-bb84-4f1a-9c2d-3e5f6a7b8c9d
status: experimental
description: Detects PowerShell execution with Base64 encoded commands, a common technique used to evade command-line logging.
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: your-github-handle
date: 2025/06/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-e '
    condition: selection
falsepositives:
    - Legitimate admin tooling using encoded commands
    - Some software installers
level: medium
```

### Once your Sigma rule is ready:
1. Translate it into your SIEM's query language using [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
2. Add enrichment (lookups, macros, asset context) specific to your environment
3. Store it in a Detection-as-Code repository with version control

**Detection-as-Code resources:**
- [Detection as Code — Splunk Blog](https://www.splunk.com/en_us/blog/learn/detection-as-code.html)
- [Getting Started with Detection-as-Code and Google SecOps](https://www.googlecloudcommunity.com/gc/Community-Blog/Getting-Started-with-Detection-as-Code-and-Google-SecOps-Part-1/ba-p/702154)
- [How Datadog implements Detection-as-Code](https://www.datadoghq.com/blog/datadog-detection-as-code/)

---

## ⑥ Validate in Dev/Test Environment

> Your first version is rarely the best. Test and tune repeatedly.

Never deploy directly to production. Run the detection in a non-production environment for at least 2–5 days to observe behaviour across different times and conditions.

**What to do:**
- Ingest test logs that should trigger the detection and confirm it fires correctly
- Simulate attack scenarios where possible to validate coverage
- Run the detection against production-equivalent data to baseline false positives
- Track outcomes and tune accordingly:

| Outcome | Action |
|---------|--------|
| Too many alerts | Add conditions, raise thresholds, add exclusions |
| No alerts on test data | Review log field mapping, check data source coverage |
| Missing edge cases | Broaden detection conditions or add variant rules |
| High noise from known-good processes | Add allow-list conditions for specific accounts/assets |

---

## ⑦ Peer Review and Stakeholder Feedback

> Feedback from the SOC and product team is essential for contextual usefulness.

A detection that looks correct on paper might create excessive noise in the hands of the SOC. Get feedback before it goes live.

**Who to involve:**
- Fellow detection engineers — review logic correctness and coverage
- SOC analysts — who will actually triage the alerts day to day
- Product or asset owners — who can clarify expected normal behaviour

**Reviewer checklist:**
- [ ] Does the detection logic accurately capture the intended behaviour?
- [ ] Is the threshold realistic and actionable for the SOC?
- [ ] Is there a runbook or playbook for SOC analysts to follow when it fires?
- [ ] Are false positive sources identified and suppressed where appropriate?
- [ ] Is the severity level correctly calibrated?

---

## ⑧ Deploy to Production

> Production rules need to be stable, documented, and monitored.

Once the detection passes peer review and SOC sign-off, deploy it to production.

**Steps:**
- Move the rule from dev/test to production in your SIEM
- Configure alert routing — Slack, email, SOAR playbook, ticketing system
- Add context to the alert template so analysts have what they need without extra investigation
- Track the first week of alerts closely for any unexpected behaviour
- Document the rule in your detection registry: hypothesis, data source, MITRE mapping, known FP sources, last review date

---

## ⑨ Maintain and Improve Continuously

> A good detection rule evolves with the environment and the threat landscape.

Detection rules are not set-and-forget. Schedule regular reviews and update them as your environment and attacker TTPs change.

**Key metrics to track:**

| Metric | What it tells you |
|--------|-------------------|
| False positive rate | Whether the rule generates actionable alerts |
| True positive rate | Whether the rule is actually catching real threats |
| Mean Time to Detect (MTTD) | How quickly the rule surfaces a real incident |
| Alert closure rate | Whether SOC analysts are triaging or ignoring the alerts |

**Triggers for a rule update:**
- SOC feedback flagging excessive noise
- New threat intelligence on updated attacker TTPs
- Product changes (API updates, field name changes, new log formats)
- New log sources becoming available that improve detection fidelity
- Periodic scheduled review (recommended: quarterly minimum)

---

## Key Resources

| Resource | Link |
|----------|------|
| SigmaHQ Rule Creation Guide | [GitHub](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide) |
| MITRE ATT&CK Framework | [attack.mitre.org](https://attack.mitre.org/) |
| Awesome Detection Engineering | [GitHub](https://github.com/infosecB/awesome-detection-engineering) |
| Detection Engineering Maturity Matrix | [detectionengineering.io](https://detectionengineering.io/) |
| Splunk Security Content | [GitHub](https://github.com/splunk/security_content/tree/develop/detections) |
| SigmaHQ Rules Library | [GitHub](https://github.com/SigmaHQ/sigma/tree/master/rules) |
| Detection Development Lifecycle — Snowflake | [Medium](https://medium.com/snowflake/detection-development-lifecycle-af166fffb3bc) |
| sigma-cli (Sigma compiler) | [GitHub](https://github.com/SigmaHQ/sigma-cli) |

---

## Credits

This checklist was inspired by the community knowledge shared across the security detection engineering space, including resources from the Sigma project, Splunk, Elastic, and the broader blue team community.
