# 🔐 Cloud Security Journey — Network Engineer to Cloud Security Engineer

> **From 6+ years of enterprise network security to AWS cloud defence — and helping other network engineers make the same transition.**

[![Security+](https://img.shields.io/badge/CompTIA-Security%2B-red?style=flat-square&logo=comptia)](https://www.comptia.org/certifications/security)
[![Forescout](https://img.shields.io/badge/Forescout-Accredited%20Engineer-blue?style=flat-square)](https://www.forescout.com)
[![AWS](https://img.shields.io/badge/AWS-Cloud%20Security-orange?style=flat-square&logo=amazon-aws)](https://aws.amazon.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Nnanna%20Okonkwo-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/nnanna2okonkow/)

---

## 👋 About This Repository

My name is **Nnanna Okonkwo**. I'm a network security engineer with over **6 years of hands-on enterprise experience** in Network Access Control, 802.1X, RADIUS, VLANs, FortiGate firewalls, and Forescout NAC deployments — holding a **Forescout Accredited Engineer** certification and **CompTIA Security+**.

This repository documents my structured, hands-on journey transitioning from enterprise network security into **AWS Cloud Security Engineering**. Every phase is built from scratch in a real AWS environment — no simulations, no shortcuts.

**Why this repo exists for two reasons:**

1. To build a verifiable, project-based cloud security portfolio that proves hands-on AWS skill beyond certifications.
2. To serve as a **practical guide for other network security engineers** who want to make the same transition into cloud — translating the concepts you already know (VLANs, ACLs, NAC, IDS) into their AWS equivalents (VPCs, Security Groups, GuardDuty, SIEM).

If you have a background in network security and want to move into cloud, this repo is built for you.

---

## 🧠 My Network Security Background → Cloud Translation

| What I knew (On-Prem) | What it maps to (AWS Cloud) |
|---|---|
| VLANs & network segmentation | VPCs, Subnets, Route Tables |
| Firewall rules (FortiGate) | Security Groups & NACLs |
| Network Access Control (Forescout) | AWS IAM, SCPs, GuardDuty |
| IDS/IPS | GuardDuty, VPC Flow Logs |
| SIEM (on-prem Wazuh) | Wazuh on AWS + CloudWatch |
| Syslog / SNMP monitoring (PRTG, Zabbix) | CloudWatch Logs & Metrics |
| Port scanning & recon (Nmap) | AWS Config, Security Hub |
| 802.1X / RADIUS authentication | AWS IAM Identity Center, Cognito |
| Network traffic capture | VPC Flow Logs → CloudWatch Logs Insights |

---

## 🗺️ Project Roadmap

| Phase | Focus Area | Status |
|---|---|---|
| **Phase 1** | Secure AWS Foundation — VPC, Subnets, Bastion Host, Hardened EC2, VPC Flow Logs, GuardDuty | ✅ Complete |
| **Phase 2** | SIEM Deployment — Wazuh on Ubuntu 22.04 LTS, log ingestion, alerting rules | 🔄 In Progress |
| **Phase 3** | IAM Hardening — Least privilege policies, MFA enforcement, IAM Access Analyser | 📋 Planned |
| **Phase 4** | Threat Detection & Automated Response — EventBridge, Lambda auto-remediation | 📋 Planned |
| **Phase 5** | Infrastructure as Code — Terraform to rebuild all phases as reusable IaC | 📋 Planned |
| **Phase 6** | Compliance & Audit — AWS Security Hub, CIS Benchmark checks, automated reporting | 📋 Planned |

---

## ✅ Phase 1 — Secure AWS Foundation

### What Was Built

A production-style secure AWS environment from scratch, following the principle of **defence in depth** — the same layered security philosophy used in enterprise network design, translated to cloud.

### Architecture

```
Internet
    │
    ▼
Internet Gateway
    │
    ▼
Public Subnet (10.0.1.0/24)
    │
  [Bastion Host] ← SSH access from trusted IP only (Security Group: Bastion-sg)
    │
    │  SSH jump (port 22, key-pair auth)
    ▼
Private Subnet (10.0.2.0/24)
    │
  [Hardened EC2] ← No direct internet access (Security Group: App-sg)
    │
VPC Flow Logs → CloudWatch Logs → Logs Insights
    │
GuardDuty → EventBridge → SNS → Email Alerts
```

### Services & Configuration

**VPC & Networking**
- Custom VPC: `security-lab-vpc` — CIDR `10.0.0.0/16`
- Public subnet: `10.0.1.0/24` (bastion host)
- Private subnet: `10.0.2.0/24` (hardened EC2, no direct internet)
- Internet Gateway attached to public subnet
- Route tables configured to enforce subnet isolation

**Security Groups**
- `Bastion-sg` — inbound SSH (port 22) restricted to trusted public IP only
- `App-sg` — inbound SSH allowed only from `Bastion-sg` (private IP), all other inbound blocked

**EC2 Instances**
- Bastion Host: Amazon Linux 2023, public subnet, key-pair authentication
- Hardened EC2: Amazon Linux 2023, private subnet, accessible only via bastion SSH jump

**VPC Flow Logs**
- Flow log: `my-flow-logs` — captures ALL traffic (accepted and rejected)
- Destination: CloudWatch Logs group `/aws/vpc/flowlogs`
- Used CloudWatch Logs Insights to query traffic by source IP, destination port, and action

**GuardDuty & Alerting**
- GuardDuty enabled across the account
- EventBridge rule filtering HIGH severity findings
- SNS topic configured — email alert confirmed received
- GuardDuty test finding used to validate the full pipeline end-to-end

### Key Concepts Demonstrated

- **Network segmentation in cloud** — public/private subnet isolation mirrors VLAN design in enterprise networks
- **Least-privilege access** — security groups act as per-instance stateful firewalls, similar to FortiGate zone policies
- **Bastion host pattern** — same jump-host concept used in secure enterprise environments, implemented in AWS
- **Traffic visibility** — VPC Flow Logs replicate the role of NetFlow/IPFIX in on-prem network monitoring
- **Threat detection pipeline** — GuardDuty → EventBridge → SNS mirrors a SIEM alert workflow

### Screenshots

> *(Screenshots coming — VPC dashboard, security groups, GuardDuty alert, CloudWatch Flow Logs query)*

---

## 🔄 Phase 2 — Wazuh SIEM Deployment (In Progress)

### What Is Being Built

Deploying **Wazuh** — an open-source SIEM and security monitoring platform — on AWS EC2 to aggregate and analyse logs from the environment built in Phase 1.

### Why Wazuh

Wazuh bridges the gap between on-prem and cloud security monitoring. In on-prem environments, tools like PRTG and Zabbix handle infrastructure monitoring, while dedicated SIEMs handle security events. Wazuh combines both — and running it on AWS means building the skill of managing a cloud-hosted SIEM, not just consuming a SaaS one.

### Deployment Specs

- Instance: `t3.medium` (2 vCPU, 4 GiB RAM)
- OS: Ubuntu 22.04 LTS (chosen over Amazon Linux 2023 due to Wazuh package compatibility)
- Storage: 30 GiB gp2
- Subnet: Private (`10.0.137.242`)
- Access: Via bastion SSH jump from Phase 1

### Progress

- [x] EC2 instance provisioned (Ubuntu 22.04 LTS, t3.medium)
- [x] Security group configured
- [x] SSH access confirmed via bastion jump
- [ ] Wazuh installation complete
- [ ] Wazuh agents configured
- [ ] Log ingestion from Phase 1 EC2 instances
- [ ] Custom detection rules
- [ ] Alert dashboard screenshots

---

## 📋 Upcoming Phases (Preview)

### Phase 3 — IAM Hardening
Enforcing least privilege across the AWS account. Creating custom IAM policies, enabling MFA, using IAM Access Analyser to detect overly permissive policies, and implementing permission boundaries. This phase maps directly to NAC policy enforcement — the same principle of "only let the right identities access the right resources" applied to cloud identity.

### Phase 4 — Automated Threat Response
Using EventBridge + Lambda to automatically respond to GuardDuty findings. For example: if GuardDuty detects unusual SSH activity, a Lambda function automatically isolates the instance by modifying its security group. This is the cloud equivalent of Forescout's automated containment actions.

### Phase 5 — Infrastructure as Code (Terraform)
Rebuilding everything from Phases 1–4 as Terraform code — making the entire environment reproducible, version-controlled, and deployable in under 10 minutes. This is what separates a cloud practitioner from a cloud engineer.

### Phase 6 — Compliance & Audit Automation
Running CIS AWS Benchmark checks via AWS Security Hub, generating compliance reports, and building automated remediation for common misconfigurations. Maps to the compliance and audit work familiar from enterprise security frameworks.

---

## 🛠️ Tools & Technologies Used

**AWS Services:** VPC · EC2 · GuardDuty · CloudWatch · CloudTrail · SNS · EventBridge · IAM · Security Hub *(upcoming)*

**Security Tools:** Wazuh SIEM · Nmap · PuTTY

**Background Tools (On-Prem):** Forescout · FortiGate · PRTG · Zabbix · 802.1X/RADIUS

**Planned:** Terraform · AWS Config · Lambda · AWS Config Rules

---

## 📁 Repository Structure

```
cloud-security-journey/
├── README.md                          ← You are here
├── Phase 1/
│   ├── README.md                      ← Phase 1 detailed write-up
│   ├── architecture-diagram.png       ← Network diagram
│   └── screenshots/                   ← AWS console evidence
├── Phase 2/                           ← In progress
│   ├── README.md
│   └── screenshots/
└── Phase 3/                           ← Coming soon
```

---

## 🤝 For Network Engineers Making the Transition

If you're a network or network security engineer looking to move into cloud security, this repository is built with you in mind. The documentation deliberately connects AWS concepts back to on-prem equivalents — because the hardest part of the transition isn't the technology, it's recognising that you already understand the principles.

Feel free to follow along, ask questions via Issues, or connect with me on LinkedIn.

**[Connect on LinkedIn →](https://www.linkedin.com/in/nnanna2okonkow/)**

---

## 📜 Certifications

- ✅ CompTIA Security+
- ✅ Forescout Accredited Engineer
- 🔄 AWS Certified Security – Specialty *(in progress)*

---

*Built in a real AWS environment. Every phase is hands-on, documented, and verifiable.*
