# Phase 2 — Detection, Logging & Incident Response

**Author:** Okonkwo Nnanna C.  
**Goal:** Build a full detection and logging pipeline — VPC Flow Logs, CloudTrail, Wazuh SIEM, GuardDuty alerts, and incident reporting.  
**Stack:** CloudWatch · VPC Flow Logs · GuardDuty · Wazuh · EventBridge · SNS  
**Status:** 🔨 In progress

---

## Architecture Overview

```
Log Sources
├── CloudTrail          → All AWS API calls (who did what, when)
├── VPC Flow Logs       → Network connections (accepted + rejected)
├── CloudWatch Agent    → OS logs from EC2 (auth, audit, system)
└── GuardDuty           → Threat intelligence findings

         ↓ all flow into ↓

CloudWatch Logs         → Central aggregation + Logs Insights queries

         ↓ splits into ↓

├── S3 Archive          → Long-term retention (90-365 days)
└── Wazuh SIEM          → Correlation, rule matching, alerting

         ↓

Alert Engine            → SNS → Email / Slack
         ↓
Incident Report         → Timeline, evidence, impact, remediation
```

---

## Step 1 — Enable VPC Flow Logs

VPC Flow Logs capture metadata on every network connection in your VPC — source IP, destination IP, port, protocol, and whether it was accepted or rejected.

### Enable via Console
1. VPC → select `security-lab-vpc` → **Flow logs** tab → **Create flow log**
2. Filter: **All**
3. Destination: **Send to CloudWatch Logs**
4. Log group: `/aws/vpc/flowlogs`
5. IAM role: click **Set up permissions** (AWS creates it automatically)

### Enable via CLI
```bash
# Get your VPC ID first
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=security-lab-vpc" \
  --query "Vpcs[0].VpcId" --output text

# Create flow log
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-XXXXXXXXX \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT_ID:role/flowlogsRole
```

### Flow Log Fields Reference

| Field | Meaning |
|---|---|
| `srcaddr` | Source IP address |
| `dstaddr` | Destination IP address |
| `srcport` | Source port |
| `dstport` | Destination port |
| `protocol` | 6=TCP, 17=UDP, 1=ICMP |
| `action` | ACCEPT or REJECT |
| `bytes` | Data transferred |
| `start` / `end` | Connection timestamp |

---

## Step 2 — CloudWatch Logs Insights Queries

Use these queries to investigate traffic patterns and detect anomalies.

### Find all rejected (blocked) traffic
```sql
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter action = "REJECT"
| sort @timestamp desc
| limit 50
```

### Find top source IPs (potential scanners)
```sql
fields srcAddr, dstAddr, dstPort
| stats count() as connections by srcAddr
| sort connections desc
| limit 20
```

### Find SSH brute force attempts (port 22 rejects)
```sql
fields @timestamp, srcAddr, dstAddr, action
| filter dstPort = 22 and action = "REJECT"
| stats count() as attempts by srcAddr
| sort attempts desc
```

### Find unusual outbound connections from private subnet
```sql
fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter srcAddr like "10.0.2."
| filter action = "ACCEPT"
| sort bytes desc
| limit 30
```

### Find CloudTrail: root account login
```sql
fields @timestamp, userIdentity.type, sourceIPAddress, eventName
| filter userIdentity.type = "Root"
| filter eventName = "ConsoleLogin"
| sort @timestamp desc
```

### Find CloudTrail: IAM changes
```sql
fields @timestamp, userIdentity.userName, eventName, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["CreateUser","DeleteUser","AttachUserPolicy","CreateAccessKey"]
| sort @timestamp desc
```

### Find CloudTrail: security group modifications
```sql
fields @timestamp, userIdentity.userName, eventName, requestParameters
| filter eventName in ["AuthorizeSecurityGroupIngress","RevokeSecurityGroupIngress"]
| sort @timestamp desc
```

---

## Step 3 — Deploy Wazuh SIEM on EC2

### Launch Wazuh EC2 Instance
- AMI: Amazon Linux 2
- Instance type: `t3.medium` (minimum 4GB RAM)
- Subnet: private subnet
- IAM role: attach `AmazonS3ReadOnlyAccess` (to read CloudTrail bucket)

### Create `wazuh-sg` Security Group

| Direction | Port | Protocol | Source | Reason |
|---|---|---|---|---|
| Inbound | 1514 | UDP | `app-sg` | Agent log shipping |
| Inbound | 1515 | TCP | `app-sg` | Agent registration |
| Inbound | 443 | TCP | `bastion-sg` | Wazuh dashboard |
| Inbound | 22 | TCP | `bastion-sg` | SSH access |

### Install Wazuh Manager

```bash
# Add Wazuh repository
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

sudo cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# Install manager
sudo yum install wazuh-manager -y
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Verify
sudo systemctl status wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log
```

### Install Wazuh Dashboard

```bash
sudo yum install wazuh-indexer wazuh-dashboard -y
sudo systemctl enable wazuh-indexer wazuh-dashboard
sudo systemctl start wazuh-indexer wazuh-dashboard
```

### Install Wazuh Agent on Each EC2

Run this on every EC2 instance you want to monitor:

```bash
sudo yum install wazuh-agent -y

# Point agent at Wazuh manager
sudo nano /var/ossec/etc/ossec.conf
```

Set the server block:
```xml
<ossec_config>
  <client>
    <server>
      <address>WAZUH_MANAGER_PRIVATE_IP</address>
      <port>1514</port>
      <protocol>udp</protocol>
    </server>
  </client>
</ossec_config>
```

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Register agent with manager (run on manager)
sudo /var/ossec/bin/manage_agents
```

### Connect CloudTrail Logs to Wazuh

Edit the Wazuh manager config to pull from your CloudTrail S3 bucket:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add:
```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>
  <bucket type="cloudtrail">
    <name>cloudtrail-logs-YOUR_ACCOUNT_ID</name>
    <aws_profile>default</aws_profile>
  </bucket>
</wodle>
```

```bash
sudo systemctl restart wazuh-manager
```

Wazuh will now ingest CloudTrail events and match them against its built-in AWS ruleset — detecting root logins, IAM changes, S3 bucket policy changes, and more.

---

## Step 4 — GuardDuty Automated Alerting via EventBridge

### Create EventBridge Rule for High Severity Findings

1. EventBridge → Rules → Create rule
2. Name: `guardduty-high-severity-alert`
3. Event pattern:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{ "numeric": [">=", 7] }]
  }
}
```

4. Target: SNS topic → `security-alerts`

### GuardDuty Severity Levels

| Severity | Score | Action |
|---|---|---|
| Low | 1.0–3.9 | Log and review weekly |
| Medium | 4.0–6.9 | Investigate within 24 hours |
| High | 7.0–8.9 | Investigate immediately |
| Critical | 9.0–10.0 | Incident response now |

### Common GuardDuty Finding Types

| Finding | What it means |
|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | SSH brute force against your EC2 |
| `Recon:EC2/PortProbeUnprotectedPort` | Port scanning of your instance |
| `CryptoCurrency:EC2/BitcoinTool.B` | EC2 connecting to crypto mining pool |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from unusual geography |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | IAM privilege escalation attempt |
| `Exfiltration:S3/ObjectRead.Unusual` | Unusual S3 data access pattern |

---

## Step 5 — Incident Report Template

Use this template for every security finding you investigate. This is what cloud security engineers produce as evidence of their work.

---

# Incident Report — [Finding Name]

**Report ID:** IR-2024-001  
**Date:** [Date of finding]  
**Severity:** High / Medium / Low  
**Status:** Open / Contained / Resolved  
**Analyst:** Okonkwo Nnanna C.

---

## 1. Executive Summary

One paragraph describing what happened, what systems were affected, and current status. Written for a non-technical audience.

---

## 2. Timeline

| Time (UTC) | Event |
|---|---|
| 14:23:05 | GuardDuty finding triggered: `UnauthorizedAccess:EC2/SSHBruteForce` |
| 14:23:10 | SNS alert received via email |
| 14:25:00 | Analyst began investigation |
| 14:30:00 | Source IP identified and blocked |
| 14:45:00 | EC2 instance verified as uncompromised |
| 15:00:00 | Incident contained |

---

## 3. Finding Details

| Field | Value |
|---|---|
| Finding type | `UnauthorizedAccess:EC2/SSHBruteForce` |
| Source | GuardDuty |
| Affected resource | `i-0abc123def456` (EC2 instance) |
| Attacker IP | `185.220.101.45` |
| Target port | 22 (SSH) |
| Attempt count | 847 attempts in 5 minutes |
| Region | eu-west-1 |
| Account ID | 123456789012 |

---

## 4. Evidence

### VPC Flow Logs — Rejected SSH Attempts
```
2024-01-15T14:23:01Z srcAddr=185.220.101.45 dstAddr=10.0.2.14 dstPort=22 action=REJECT
2024-01-15T14:23:02Z srcAddr=185.220.101.45 dstAddr=10.0.2.14 dstPort=22 action=REJECT
[847 similar entries]
```

### CloudWatch Logs Insights Query Used
```sql
fields @timestamp, srcAddr, dstAddr, action
| filter dstPort = 22 and action = "REJECT"
| filter srcAddr = "185.220.101.45"
| sort @timestamp desc
```

### GuardDuty Finding JSON
```json
{
  "type": "UnauthorizedAccess:EC2/SSHBruteForce",
  "severity": 8.0,
  "title": "847 SSH brute force login attempts",
  "description": "EC2 instance i-0abc123def456 is being probed...",
  "service": {
    "action": {
      "networkConnectionAction": {
        "remoteIpDetails": {
          "ipAddressV4": "185.220.101.45",
          "country": { "countryName": "Germany" }
        }
      }
    },
    "count": 847
  }
}
```

---

## 5. Impact Assessment

| Area | Assessment |
|---|---|
| Data breach | No — all attempts were REJECTED by security group |
| System compromise | No — SSH password auth disabled, key-based only |
| Service disruption | None |
| Data integrity | Not affected |

---

## 6. Root Cause

The EC2 instance was targeted by an automated SSH brute force scanner. The attack was unsuccessful because:
- Security group `app-sg` only allows SSH from `bastion-sg`, not from the internet
- SSH password authentication is disabled — key-based auth only
- fail2ban would have banned the IP at OS level if traffic had reached the instance

The security controls from Phase 1 hardening worked as intended.

---

## 7. Remediation Actions Taken

| Action | Status | Time |
|---|---|---|
| Source IP `185.220.101.45` added to NACL deny list | Complete | 14:30 UTC |
| EC2 instance auth logs reviewed — no successful logins | Complete | 14:35 UTC |
| CloudTrail reviewed — no API calls from attacker IP | Complete | 14:40 UTC |
| GuardDuty finding marked as resolved | Complete | 15:00 UTC |
| IP reported to AbuseIPDB | Complete | 15:05 UTC |

---

## 8. Lessons Learned

- Detection to alert took 5 seconds — GuardDuty + EventBridge + SNS pipeline working correctly
- All Phase 1 hardening controls (security groups, disabled password auth, private subnet) prevented compromise
- Recommend adding NACL geo-blocking rule to reduce noise from known Tor exit nodes

---

## 9. References

- GuardDuty finding ID: `abc123def456`
- CloudWatch log group: `/aws/vpc/flowlogs`
- Wazuh alert ID: `WZ-2024-0115-001`
- AbuseIPDB report: [link]

---

*End of incident report*

---

## Phase 2 Completion Checklist

| Task | Done? |
|---|---|
| VPC Flow Logs enabled (All traffic) | |
| Flow logs shipping to CloudWatch | |
| CloudWatch Logs Insights queries tested | |
| Wazuh manager deployed on EC2 | |
| Wazuh agent installed on hardened EC2 | |
| CloudTrail S3 bucket connected to Wazuh | |
| GuardDuty EventBridge rule created | |
| SNS alert tested (receive test email) | |
| First incident report written | |

---

## Skills Translation

| Prior experience | Phase 2 equivalent |
|---|---|
| Zabbix SNMP traps and alerts | CloudWatch alarms + EventBridge rules |
| PRTG network monitoring | VPC Flow Logs + Logs Insights |
| Wazuh (on-premise) | Wazuh on EC2 + CloudTrail integration |
| Nmap scan reports | AWS Inspector findings + GuardDuty reports |
| Social engineering seminar reports | Incident report writing |
| Network topology documentation | Architecture diagrams + GitHub docs |

---

## Next Steps → Phase 3

- [ ] Write a Python/Boto3 script to auto-pull GuardDuty findings
- [ ] Build a Lambda function to auto-remediate low-severity findings
- [ ] Connect Claude API to auto-generate incident reports from raw findings
- [ ] Deploy the full AI security agent

---

*Part of my Cloud Security Engineer learning path — Phase 2: Detection and Logging.*
