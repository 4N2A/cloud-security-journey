# Phase 1 — AWS Account Setup & Security Hardening

**Author:** Okonkwo Nnanna C.  
**Goal:** Set up and harden a fresh AWS account the way a Cloud Security Engineer would.  
**Stack:** AWS Console · IAM · VPC · CloudWatch · AWS CLI  
**Status:** 🔨 In progress

---

## Why This Matters

When you create an AWS account, it ships insecure by default. The root account has unlimited power, no multi-factor authentication (MFA) is enforced, billing has no alerts, and anyone with credentials can spin up resources in any region. A cloud security engineer's first job is to lock this down *before* deploying anything.

This document covers exactly that — modelled on real-world best practices (CIS AWS Foundations Benchmark).

---

## Step 1 — Secure the Root Account

The root account is the most powerful identity in AWS. It should never be used for day-to-day tasks.

### Actions
1. **Enable MFA on root** — go to IAM → Security credentials → Assign MFA device. Use a hardware key (YubiKey) or authenticator app (Google Authenticator / Authy).
2. **Delete root access keys** — if any exist, delete them immediately. Root should never have programmatic access.
3. **Set a strong password** — minimum 16 characters, stored in a password manager.
4. **Lock the root account away** — use it only for account-level actions (e.g. closing the account, changing the support plan).

### Why
If root credentials are compromised, an attacker has complete control — they can delete all resources, exfiltrate data, and lock you out. There is no recovery without contacting AWS support.

---

## Step 2 — Enable Billing Alerts

Before spending a single dollar, set up cost protection. Attackers who compromise an account will often spin up GPU instances for crypto mining — billing alerts catch this fast.

### Actions
1. Go to **Billing Console** → Billing Preferences → enable "Receive Billing Alerts".
2. Go to **CloudWatch** → Alarms → Create Alarm → Select metric → Billing → Total Estimated Charge.
3. Set a threshold (e.g. $5 for a lab account) and send alert to your email via SNS.

### CLI equivalent
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "billing-alert-5usd" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --dimensions Name=Currency,Value=USD \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:billing-alerts \
  --treat-missing-data notBreaching
```

---

## Step 3 — Create an Admin IAM User (Stop Using Root)

Never use root for daily work. Create a dedicated IAM user with admin privileges instead.

### Actions
1. Go to **IAM** → Users → Add user.
2. Name: `admin-nnanna` (or your preferred naming convention).
3. Attach policy: `AdministratorAccess` (for your personal lab — in production, use a custom policy).
4. Enable **MFA** on this user too.
5. Generate **Access Keys** for CLI use — store securely, never commit to GitHub.

### Principle of Least Privilege
In production environments, nobody gets `AdministratorAccess`. Instead, you create roles scoped to specific tasks:

| Role | Permissions |
|---|---|
| `SecurityAuditorRole` | Read-only access to IAM, CloudTrail, GuardDuty |
| `EC2OperatorRole` | Start/stop EC2 only, no IAM changes |
| `S3ReaderRole` | Read-only access to specific S3 buckets |

---

## Step 4 — Set Up IAM Password Policy

Enforce strong passwords for all IAM users in the account.

### Actions
Go to **IAM** → Account settings → Set password policy:

| Setting | Value |
|---|---|
| Minimum length | 14 characters |
| Require uppercase | ✅ |
| Require lowercase | ✅ |
| Require numbers | ✅ |
| Require symbols | ✅ |
| Password expiry | 90 days |
| Prevent reuse | Last 24 passwords |

### CLI equivalent
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24
```

---

## Step 5 — Enable AWS CloudTrail (Audit Log)

CloudTrail records every API call made in your account — who did what, when, and from where. This is your forensic trail.

### Actions
1. Go to **CloudTrail** → Create trail.
2. Name: `management-trail`.
3. Enable for **all regions** (not just one).
4. Store logs in a dedicated S3 bucket: `cloudtrail-logs-[account-id]`.
5. Enable **log file validation** — detects if logs are tampered with.
6. Enable **CloudWatch Logs integration** — allows alerting on specific API calls.

### Key events to monitor
- `ConsoleLogin` — every login to the console
- `CreateUser` / `DeleteUser` — IAM changes
- `AuthorizeSecurityGroupIngress` — firewall rule changes
- `StopLogging` — someone trying to disable CloudTrail (critical alert!)

---

## Step 6 — Build a Secure VPC

Think of a VPC as your private data centre in AWS. Like a network you'd build with VLANs and firewall zones — except defined in code.

### Architecture

```
Internet
    |
[Internet Gateway]
    |
[Public Subnet]  ← Load balancers, bastion hosts only
    |
[NAT Gateway]
    |
[Private Subnet] ← EC2 instances, databases — no direct internet access
```

### Actions
1. Go to **VPC** → Create VPC.
2. CIDR block: `10.0.0.0/16`
3. Create **public subnet**: `10.0.1.0/24` (attach Internet Gateway)
4. Create **private subnet**: `10.0.2.0/24` (attach NAT Gateway for outbound only)
5. Create **Security Groups**:
   - `web-sg`: allow inbound 443 from 0.0.0.0/0, deny everything else
   - `db-sg`: allow inbound 5432 from `web-sg` only (no public access)
   - `bastion-sg`: allow SSH (port 22) from your IP only

### Your networking background in AWS terms

| Your skill | AWS equivalent |
|---|---|
| VLAN segmentation | Subnets (public/private) |
| Firewall rules (FortiGate) | Security Groups + NACLs |
| NAC (Forescout) | IAM + VPC Endpoint Policies |
| Network monitoring (Zabbix) | VPC Flow Logs + CloudWatch |

---

## Step 7 — Enable GuardDuty

GuardDuty is AWS's built-in threat detection service. It analyses CloudTrail, VPC Flow Logs, and DNS logs for suspicious behaviour — think of it as your cloud SIEM sensor.

### Actions
1. Go to **GuardDuty** → Enable GuardDuty.
2. Enable for all regions.
3. Set up **SNS notification** for HIGH severity findings.

### What GuardDuty detects
- Credential compromise (logins from unusual geographies)
- Crypto mining (EC2 instances connecting to known mining pools)
- Port scanning from your instances
- Privilege escalation attempts

---

## Step 8 — CIS AWS Benchmark Checklist

The Center for Internet Security (CIS) AWS Foundations Benchmark is the industry standard for AWS account hardening. Use this as your audit checklist.

| Check | Status |
|---|---|
| MFA enabled on root account | ✅ |
| Root account has no access keys | ✅ |
| MFA enabled for all IAM users | ✅ |
| IAM password policy enforced | ✅ |
| CloudTrail enabled in all regions | ✅ |
| CloudTrail log file validation enabled | ✅ |
| Billing alerts configured | ✅ |
| S3 bucket with CloudTrail logs not publicly accessible | ✅ |
| GuardDuty enabled | ✅ |
| No security groups allow 0.0.0.0/0 on port 22 (SSH) | ✅ |
| No security groups allow 0.0.0.0/0 on port 3389 (RDP) | ✅ |
| VPC Flow Logs enabled | ✅ |

---

## Skills Translation: Network → Cloud

| What you did at Creastech / Nigerian Ports Authority | What this maps to in AWS |
|---|---|
| Configured FortiGate firewall rules | AWS Security Groups + NACLs + WAF |
| Deployed Forescout NAC with RADIUS/EAP | AWS IAM + 802.1X via AWS Directory Service |
| Monitored network with Zabbix / PRTG | CloudWatch + GuardDuty + Security Hub |
| Ran Nmap vulnerability scans | AWS Inspector |
| Configured VLANs | VPC Subnets |
| Backup and DR with Synology | S3 + AWS Backup + cross-region replication |

---

## Next Steps → Phase 2

- [ ] Enable VPC Flow Logs and ship to CloudWatch
- [ ] Deploy Wazuh SIEM on EC2 and ingest CloudTrail logs
- [ ] Write first incident report from a real GuardDuty finding
- [ ] Explore AWS Security Hub for consolidated findings

---

## Resources

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [GuardDuty docs](https://docs.aws.amazon.com/guardduty/)

---

*Part of my Cloud Security Engineer learning path. Built hands-on, documented for GitHub.*
