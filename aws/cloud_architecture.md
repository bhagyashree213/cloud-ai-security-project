# CloudSentinel AWS Cloud Architecture & Infrastructure Guide

## 1. High-Level Architecture Overview

CloudSentinel deploys across a resilient, multi-tiered AWS cloud architecture:

```text
                                 [ USER / ANALYST ]
                                         │
                                         ▼
                            [ AWS Route 53 / DNS ]
                                         │
                                         ▼
                      [ AWS Application Load Balancer / TLS ]
                                         │ (Port 8501)
                                         ▼
            ┌─────────────────────────────────────────────────────────┐
            │                  AWS VPC (10.0.0.0/16)                  │
            │                                                         │
            │  ┌───────────────────────────────────────────────────┐  │
            │  │        Public Subnet (10.0.1.0/24)                │  │
            │  │                                                   │  │
            │  │  [ Amazon EC2 Instance (t3.medium / Ubuntu 22.04) ]│  │
            │  │    • Streamlit Application Server (app.py)        │  │
            │  │    • Scikit-learn AI Inference Pipeline           │  │
            │  │    • Systemd background daemon                    │  │
            │  │    • Attached IAM Role (Least Privilege)          │  │
            │  └─────────────────────────┬─────────────────────────┘  │
            │                            │                            │
            │  ┌─────────────────────────┼─────────────────────────┐  │
            │  │ Private Subnet (10.0.2.0/24)                      │  │
            │  │                         ▼                         │  │
            │  │       [ Amazon RDS (PostgreSQL / MySQL) ]         │  │
            │  │         • security_logs, threats, alerts          │  │
            │  │         • Security Group restricted to EC2 SG     │  │
            │  └───────────────────────────────────────────────────┘  │
            └────────────────────────────┬────────────────────────────┘
                                         │
                                         ▼
                  [ Amazon S3 Secure Storage Vault (AES256) ]
                    • s3://<bucket>/datasets/
                    • s3://<bucket>/logs/
                    • s3://<bucket>/reports/
                    • s3://<bucket>/backups/
```

---

## 2. Security Group Configuration

### A. EC2 Security Group (`sg-cloudsentinel-ec2`)
| Type | Protocol | Port Range | Source | Description |
| :--- | :--- | :--- | :--- | :--- |
| Inbound | TCP | 22 | Administrator IP (`x.x.x.x/32`) | Secure Shell (SSH) access |
| Inbound | TCP | 8501 | `0.0.0.0/0` (or ALB SG) | Streamlit Web User Interface |
| Outbound | All | All | `0.0.0.0/0` | Outbound Internet for S3 / Boto3 / Packages |

### B. RDS Security Group (`sg-cloudsentinel-rds`)
| Type | Protocol | Port Range | Source | Description |
| :--- | :--- | :--- | :--- | :--- |
| Inbound | TCP | 5432 (Postgres) / 3306 (MySQL) | `sg-cloudsentinel-ec2` | Private DB traffic strictly from EC2 application |
| Outbound | None | None | None | Database locked in private subnet |

---

## 3. AWS IAM Instance Profile Configuration

To eliminate hardcoded credentials and prevent access key leaks:
1. Create an IAM Role named `CloudSentinelEC2Role`.
2. Attach the least-privilege policy from `aws/iam_policy.json`.
3. Attach `CloudSentinelEC2Role` directly to the EC2 instance via the AWS EC2 Console: **Actions ➔ Security ➔ Modify IAM role**.
4. The Python Boto3 client automatically discovers temporary credentials via the EC2 Instance Metadata Service (IMDSv2).
