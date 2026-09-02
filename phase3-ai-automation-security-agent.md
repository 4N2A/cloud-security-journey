# Phase 3 — AI Automation & Security Agent

**Author:** Okonkwo Nnanna C.  
**Goal:** Automate security operations using Python/Boto3, AWS Lambda, and the Claude AI API to build an intelligent security agent that detects, analyses, and responds to threats automatically.  
**Stack:** Python · Boto3 · AWS Lambda · Claude API (Anthropic) · GuardDuty · SNS · S3 · IAM  
**Status:** 🔨 In progress

---

## Architecture Overview

```
GuardDuty Finding
      ↓
EventBridge Rule (severity >= 7)
      ↓
Lambda Function — auto-remediation
      ↓
┌─────────────────────────────┐
│  Low severity  → SNS alert  │
│  Medium        → Block IP   │
│  High/Critical → Isolate EC2│
└─────────────────────────────┘
      ↓
Claude AI API
      ↓
Auto-generated Incident Report (PDF/Markdown)
      ↓
S3 → Email via SNS
```

---

## What You Will Build

| Component | What it does |
|---|---|
| `guardduty_puller.py` | Python/Boto3 script to pull and display GuardDuty findings |
| `lambda_auto_remediate.py` | Lambda function to auto-remediate low/medium severity findings |
| `claude_report_generator.py` | Connects Claude API to raw findings and generates incident reports |
| `security_agent.py` | Full AI security agent combining all three components |

---

## Prerequisites

Before starting Phase 3, confirm Phase 2 is complete:

- [x] Wazuh agents connected (Bastion + Hardened-EC2)
- [x] CloudTrail → S3 → Wazuh ingestion working
- [x] GuardDuty EventBridge rule active (`guardduty-high-severity-alert`)
- [x] SNS topic `security-alerts` sending emails
- [x] First incident report written (IR-2026-001)

---

## Step 1 — Python/Boto3 Script to Pull GuardDuty Findings

This script connects to GuardDuty via the AWS SDK and pulls all current findings, sorted by severity. It's the foundation everything else builds on.

### Install dependencies (on your bastion)

```bash
sudo apt install python3-pip -y
pip3 install boto3 --break-system-packages
```

### Verify AWS credentials are configured

```bash
aws configure list
aws guardduty list-detectors --region us-east-1
```

Note the detector ID — you'll need it for all GuardDuty API calls.

### `guardduty_puller.py`

```python
import boto3
import json
from datetime import datetime

# Configuration
REGION = 'us-east-1'
SEVERITY_LABELS = {
    (0, 4): 'LOW',
    (4, 7): 'MEDIUM',
    (7, 9): 'HIGH',
    (9, 10.1): 'CRITICAL'
}

def get_severity_label(score):
    for (low, high), label in SEVERITY_LABELS.items():
        if low <= score < high:
            return label
    return 'UNKNOWN'

def get_detector_id(client):
    response = client.list_detectors()
    detectors = response.get('DetectorIds', [])
    if not detectors:
        raise Exception("No GuardDuty detector found. Enable GuardDuty first.")
    return detectors[0]

def pull_findings(min_severity=1.0):
    client = boto3.client('guardduty', region_name=REGION)
    detector_id = get_detector_id(client)
    print(f"Detector ID: {detector_id}")

    # List finding IDs
    response = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'severity': {
                    'Gte': int(min_severity * 10)
                }
            }
        },
        SortCriteria={
            'AttributeName': 'severity',
            'OrderBy': 'DESC'
        },
        MaxResults=50
    )

    finding_ids = response.get('FindingIds', [])
    if not finding_ids:
        print("No findings found.")
        return []

    # Get full finding details
    findings_response = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )

    findings = findings_response.get('Findings', [])
    print(f"\nFound {len(findings)} findings:\n")
    print("-" * 80)

    for f in findings:
        severity = f.get('Severity', 0)
        label = get_severity_label(severity)
        print(f"[{label}] Severity: {severity}")
        print(f"  Type:        {f.get('Type', 'N/A')}")
        print(f"  Title:       {f.get('Title', 'N/A')}")
        print(f"  Description: {f.get('Description', 'N/A')[:100]}...")
        print(f"  Region:      {f.get('Region', 'N/A')}")
        print(f"  Account:     {f.get('AccountId', 'N/A')}")
        print(f"  Updated:     {f.get('UpdatedAt', 'N/A')}")
        print(f"  Finding ID:  {f.get('Id', 'N/A')}")
        print("-" * 80)

    return findings

if __name__ == '__main__':
    findings = pull_findings(min_severity=1.0)
    print(f"\nTotal findings pulled: {len(findings)}")
```

### Run it

```bash
python3 guardduty_puller.py
```

Expected output shows all GuardDuty findings sorted by severity with full details.

---

## Step 2 — Lambda Function for Auto-Remediation

This Lambda function is triggered automatically by EventBridge when GuardDuty fires a finding. It takes action based on severity without any human intervention.

### Remediation Logic

| Severity | Score | Automated Action |
|---|---|---|
| Low | 1.0–3.9 | Send SNS notification only |
| Medium | 4.0–6.9 | Send SNS + add IP to NACL blocklist |
| High | 7.0–8.9 | Send SNS + isolate EC2 instance (remove from SG) |
| Critical | 9.0–10.0 | Send SNS + isolate EC2 + snapshot EBS for forensics |

### Create IAM role for Lambda

Go to **IAM → Roles → Create role**:
- Trusted entity: Lambda
- Policies to attach:
  - `AmazonGuardDutyReadOnlyAccess`
  - `AmazonEC2FullAccess`
  - `AmazonSNSFullAccess`
  - `AWSLambdaBasicExecutionRole`
- Role name: `lambda-security-remediation-role`

### `lambda_auto_remediate.py`

```python
import boto3
import json
import os
from datetime import datetime

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
REGION = os.environ.get('AWS_REGION', 'us-east-1')

ec2 = boto3.client('ec2', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

def lambda_handler(event, context):
    """
    Triggered by EventBridge on GuardDuty findings.
    Event structure: GuardDuty Finding JSON from EventBridge.
    """
    print(f"Event received: {json.dumps(event)}")

    detail = event.get('detail', {})
    severity = detail.get('severity', 0)
    finding_type = detail.get('type', 'Unknown')
    title = detail.get('title', 'No title')
    description = detail.get('description', '')
    finding_id = detail.get('id', '')
    account_id = detail.get('accountId', '')

    # Extract affected resource details
    resource = detail.get('resource', {})
    instance_id = (resource.get('instanceDetails', {}) or {}).get('instanceId')
    remote_ip = (
        detail.get('service', {})
        .get('action', {})
        .get('networkConnectionAction', {})
        .get('remoteIpDetails', {})
        .get('ipAddressV4')
    )

    severity_label = get_severity_label(severity)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %Human:%M:%S UTC')

    print(f"Severity: {severity} ({severity_label})")
    print(f"Type: {finding_type}")
    print(f"Instance: {instance_id}")
    print(f"Remote IP: {remote_ip}")

    actions_taken = []

    # Always send SNS alert
    alert_message = build_alert_message(
        severity_label, severity, finding_type,
        title, description, instance_id,
        remote_ip, finding_id, account_id, timestamp
    )
    send_sns_alert(alert_message, f"[{severity_label}] GuardDuty: {finding_type}")
    actions_taken.append("SNS alert sent")

    # Medium severity: block the source IP at NACL level
    if severity >= 4.0 and remote_ip:
        result = block_ip_in_nacl(remote_ip)
        actions_taken.append(f"IP {remote_ip} blocked in NACL: {result}")

    # High severity: isolate the EC2 instance
    if severity >= 7.0 and instance_id:
        result = isolate_instance(instance_id)
        actions_taken.append(f"EC2 {instance_id} isolated: {result}")

    # Critical: also snapshot for forensics
    if severity >= 9.0 and instance_id:
        result = snapshot_instance(instance_id)
        actions_taken.append(f"EBS snapshot created: {result}")

    print(f"Actions taken: {actions_taken}")
    return {
        'statusCode': 200,
        'finding_id': finding_id,
        'severity': severity_label,
        'actions_taken': actions_taken
    }

def get_severity_label(score):
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    return 'LOW'

def build_alert_message(label, score, finding_type, title,
                        description, instance_id, remote_ip,
                        finding_id, account_id, timestamp):
    return f"""
GUARDDUTY SECURITY ALERT — {label} (Score: {score})
{'=' * 60}
Time:        {timestamp}
Finding:     {finding_type}
Title:       {title}
Description: {description}

Affected Resource: {instance_id or 'N/A'}
Source IP:         {remote_ip or 'N/A'}
Finding ID:        {finding_id}
Account:           {account_id}
{'=' * 60}
Automated remediation has been triggered based on severity.
Review the Wazuh dashboard and CloudTrail for full details.
"""

def send_sns_alert(message, subject):
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set — skipping SNS")
        return
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject=subject[:100]
    )
    print("SNS alert sent")

def block_ip_in_nacl(ip_address):
    """Add a DENY rule to the default NACL for the source IP."""
    try:
        nacls = ec2.describe_network_acls(
            Filters=[{'Name': 'default', 'Values': ['true']}]
        )
        nacl_id = nacls['NetworkAcls'][0]['NetworkAclId']
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=1,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f"{ip_address}/32"
        )
        return f"Blocked {ip_address}/32 in NACL {nacl_id}"
    except Exception as e:
        return f"NACL block failed: {str(e)}"

def isolate_instance(instance_id):
    """Move instance to an isolation security group."""
    try:
        # Get current security groups
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        print(f"Current SGs: {current_sgs}")

        # Ideally create/use a dedicated isolation SG with no inbound/outbound
        # For now, tag instance as isolated for manual review
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'SecurityStatus', 'Value': 'ISOLATED'},
                {'Key': 'IsolationTime', 'Value': datetime.utcnow().isoformat()},
                {'Key': 'IsolationReason', 'Value': 'GuardDuty High Severity Finding'}
            ]
        )
        return f"Instance {instance_id} tagged as ISOLATED"
    except Exception as e:
        return f"Isolation failed: {str(e)}"

def snapshot_instance(instance_id):
    """Create EBS snapshots of all volumes for forensic analysis."""
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        volumes = [
            bdm['Ebs']['VolumeId']
            for bdm in instance.get('BlockDeviceMappings', [])
            if 'Ebs' in bdm
        ]
        snapshot_ids = []
        for vol_id in volumes:
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"Forensic snapshot - GuardDuty finding - {instance_id}",
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Purpose', 'Value': 'ForensicSnapshot'},
                        {'Key': 'InstanceId', 'Value': instance_id},
                        {'Key': 'CreatedBy', 'Value': 'SecurityAgent'}
                    ]
                }]
            )
            snapshot_ids.append(snap['SnapshotId'])
        return f"Snapshots created: {snapshot_ids}"
    except Exception as e:
        return f"Snapshot failed: {str(e)}"
```

### Deploy to Lambda

1. **AWS Console → Lambda → Create function**
2. Name: `guardduty-auto-remediate`
3. Runtime: Python 3.12
4. Execution role: `lambda-security-remediation-role`
5. Paste the code above
6. Add environment variable: `SNS_TOPIC_ARN` = your SNS topic ARN
7. Set timeout to **30 seconds**

### Connect EventBridge to Lambda

Go to your existing `guardduty-high-severity-alert` EventBridge rule:
- **Edit → Targets → Add target → Lambda function**
- Select `guardduty-auto-remediate`

---

## Step 3 — Connect Claude API to Auto-Generate Incident Reports

This script takes a raw GuardDuty finding and feeds it to the Claude API, which generates a complete, professional incident report automatically.

### Install Anthropic SDK (on bastion)

```bash
pip3 install anthropic --break-system-packages
```

### `claude_report_generator.py`

```python
import anthropic
import boto3
import json
from datetime import datetime

REGION = 'us-east-1'

def get_latest_finding():
    """Pull the most recent high-severity GuardDuty finding."""
    client = boto3.client('guardduty', region_name=REGION)
    detectors = client.list_detectors()['DetectorIds']
    detector_id = detectors[0]

    finding_ids = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'severity': {'Gte': 40}  # Medium and above (score * 10)
            }
        },
        SortCriteria={'AttributeName': 'severity', 'OrderBy': 'DESC'},
        MaxResults=1
    )['FindingIds']

    if not finding_ids:
        return None

    findings = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']

    return findings[0] if findings else None

def generate_incident_report(finding):
    """Send finding to Claude API and get a full incident report back."""
    anthropic_client = anthropic.Anthropic()

    finding_json = json.dumps(finding, indent=2, default=str)
    today = datetime.utcnow().strftime('%B %d, %Y')

    prompt = f"""You are a cloud security engineer writing a formal incident report.

Analyse this GuardDuty finding and write a complete incident report in Markdown format.

The report must include:
1. Executive Summary (2-3 sentences, non-technical)
2. Timeline of Events (table format, infer reasonable times)
3. Finding Details (table with: type, severity, affected resource, source IP, region, account)
4. Impact Assessment (table: data breach, service disruption, data integrity, exposure window)
5. Root Cause Analysis
6. Remediation Actions Taken (table with action, status, time)
7. Lessons Learned (3-4 bullet points)
8. References

Use today's date: {today}
Analyst: Okonkwo Nnanna C.
Report ID: IR-{datetime.utcnow().strftime('%Y-%m%d')}-AUTO

GuardDuty Finding:
{finding_json}

Write the full report now. Be specific — use the actual finding data, not placeholders."""

    message = anthropic_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4000,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return message.content[0].text

def save_report(report_text, finding_type):
    """Save the generated report to a markdown file."""
    safe_name = finding_type.replace(':', '-').replace('/', '-')
    filename = f"IR-AUTO-{datetime.utcnow().strftime('%Y%m%d-%H%M')}-{safe_name}.md"
    with open(filename, 'w') as f:
        f.write(report_text)
    print(f"Report saved to: {filename}")
    return filename

def main():
    print("Pulling latest GuardDuty finding...")
    finding = get_latest_finding()

    if not finding:
        print("No findings found. Generating sample report with test data...")
        # Use a sample finding for demonstration if no live findings exist
        finding = {
            "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "Severity": 8.0,
            "Title": "SSH brute force attack detected",
            "Description": "EC2 instance is being probed on port 22.",
            "Region": "us-east-1",
            "AccountId": "037613907516",
            "UpdatedAt": datetime.utcnow().isoformat()
        }

    print(f"Finding type: {finding.get('Type')}")
    print(f"Severity: {finding.get('Severity')}")
    print("\nSending to Claude API for report generation...")

    report = generate_incident_report(finding)
    filename = save_report(report, finding.get('Type', 'unknown'))

    print("\n" + "=" * 60)
    print("GENERATED INCIDENT REPORT:")
    print("=" * 60)
    print(report[:2000] + "..." if len(report) > 2000 else report)

if __name__ == '__main__':
    main()
```

### Get your Anthropic API key

1. Go to **console.anthropic.com → API Keys → Create Key**
2. Copy the key
3. Set it as an environment variable on your bastion:

```bash
export ANTHROPIC_API_KEY="your-key-here"
echo 'export ANTHROPIC_API_KEY="your-key-here"' >> ~/.bashrc
```

### Run it

```bash
python3 claude_report_generator.py
```

---

## Step 4 — Deploy the Full AI Security Agent

The security agent combines all three components into a single automated system that runs continuously.

### `security_agent.py`

```python
import boto3
import json
import time
import anthropic
from datetime import datetime
from guardduty_puller import pull_findings
from claude_report_generator import generate_incident_report, save_report

REGION = 'us-east-1'
POLL_INTERVAL = 300  # Check every 5 minutes
PROCESSED_FINDINGS = set()

def run_agent():
    """Main agent loop — polls GuardDuty and responds to new findings."""
    print(f"AI Security Agent started at {datetime.utcnow()}")
    print(f"Polling every {POLL_INTERVAL} seconds...\n")

    while True:
        try:
            print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Checking for new findings...")
            findings = pull_findings(min_severity=4.0)

            new_findings = [
                f for f in findings
                if f.get('Id') not in PROCESSED_FINDINGS
            ]

            if new_findings:
                print(f"Found {len(new_findings)} new finding(s) to process")
                for finding in new_findings:
                    process_finding(finding)
                    PROCESSED_FINDINGS.add(finding.get('Id'))
            else:
                print("No new findings.")

        except Exception as e:
            print(f"Agent error: {e}")

        time.sleep(POLL_INTERVAL)

def process_finding(finding):
    """Process a single finding — generate report and trigger remediation."""
    severity = finding.get('Severity', 0)
    finding_type = finding.get('Type', 'Unknown')
    print(f"\nProcessing: {finding_type} (Severity: {severity})")

    # Generate AI incident report
    print("Generating incident report via Claude API...")
    report = generate_incident_report(finding)
    filename = save_report(report, finding_type)
    print(f"Report saved: {filename}")

    # Log summary to console
    print(f"Processed finding: {finding_type}")
    print(f"Severity: {severity}")
    print(f"Report: {filename}")

if __name__ == '__main__':
    run_agent()
```

### Run the agent

```bash
# Run in the foreground to watch it work
python3 security_agent.py

# Or run as a background service
nohup python3 security_agent.py > agent.log 2>&1 &
tail -f agent.log
```

---

## Testing the Full Pipeline

### Generate a test GuardDuty finding

```bash
# GuardDuty has a built-in sample findings generator
aws guardduty create-sample-findings \
  --detector-id YOUR_DETECTOR_ID \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" \
  --region us-east-1
```

This creates a realistic sample finding that triggers the full pipeline:
1. GuardDuty finding created
2. EventBridge rule fires
3. Lambda auto-remediates
4. Security agent detects it
5. Claude API generates incident report
6. SNS email sent to you

---

## Phase 3 Completion Checklist

| Task | Done? |
|---|---|
| Python/Boto3 GuardDuty puller script working | |
| Script pulls and displays findings with severity labels | |
| Lambda function created with correct IAM role | |
| Lambda connected to EventBridge GuardDuty rule | |
| Lambda tested with sample finding | |
| Anthropic API key configured on bastion | |
| Claude report generator pulling live findings | |
| Claude generating full markdown incident reports | |
| Full security agent running and polling | |
| End-to-end test: finding → Lambda → report → email | |

---

## Skills Translation

| Prior experience | Phase 3 equivalent |
|---|---|
| Zabbix alerting scripts | Python/Boto3 GuardDuty automation |
| Manual incident reporting | Claude AI auto-generated reports |
| Network monitoring dashboards | Security agent continuous polling |
| Forescout NAC automated responses | Lambda auto-remediation functions |
| PRTG alert escalation | EventBridge → Lambda → SNS pipeline |

---

## Cost Estimate

| Service | Usage | Estimated Cost |
|---|---|---|
| Lambda | <1M invocations/month | Free tier |
| GuardDuty | Already enabled | ~$1-3/month |
| Claude API (Sonnet) | ~100 reports/month | ~$1-2/month |
| SNS | <1000 emails/month | Free tier |
| **Total** | | **~$2-5/month** |

---

## Next Steps → Phase 4

- [ ] Build a Streamlit or React dashboard to visualise findings
- [ ] Add Slack integration for real-time alerts
- [ ] Implement automated NACL geo-blocking by country
- [ ] Deploy infrastructure as code using Terraform
- [ ] Write a full SOC playbook for each finding type

---

*Part of my Cloud Security Engineer learning path — Phase 3: AI Automation & Security Agent.*
