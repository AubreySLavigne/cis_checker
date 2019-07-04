# Development Progress

Below are all 49 benchmarks.

[x] = Implemented

[?] = Intended Next to Implement

## 1 Identity and Access Management

| # | Audit | Fix | Profile Level | Description |
| 1.1 | [ ] | [ ] | 1 | Avoid the use of the "root" account |
| 1.2 | [ ] | [ ] | 1 | Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password |
| 1.3 | [ ] | [ ] | 1 | Ensure credentials unused for 90 days or greater are disabled |
| 1.4 | [ ] | [ ] | 1 | Ensure access keys are rotated every 90 days or less |
| 1.5 | [x] | [ ] | 1 | Ensure IAM password policy requires at least one uppercase letter |
| 1.6 | [x] | [ ] | 1 | Ensure IAM password policy require at least one lowercase letter |
| 1.7 | [x] | [ ] | 1 | Ensure IAM password policy require at least one symbol |
| 1.8 | [x] | [ ] | 1 | Ensure IAM password policy require at least one number |
| 1.9 | [x] | [ ] | 1 | Ensure IAM password policy requires minimum length of 14 or greater |
| 1.10 | [x] | [ ] | 1 | Ensure IAM password policy prevents password reuse |
| 1.11 | [x] | [ ] | 1 | Ensure IAM password policy expires passwords within 90 days or less |
| 1.12 | [ ] | [ ] | 1 | Ensure no root account access key exists |
| 1.13 | [?] | [ ] | 1 | Ensure MFA is enabled for the "root" account |
| 1.14 | [?] | [ ] | 2 | Ensure hardware MFA is enabled for the "root" account |
| 1.15 | [ ] | [ ] | 1 | Ensure security questions are registered in the AWS account |
| 1.16 | [?] | [ ] | 1 | Ensure IAM policies are attached only to groups or roles |
| 1.17 | [ ] | [ ] | 1 | Maintain current contact details |
| 1.18 | [ ] | [ ] | 1 | Ensure security contact information is registered |
| 1.19 | [ ] | [ ] | 2 | Ensure IAM instance roles are used for AWS resource access from instances |
| 1.20 | [?] | [ ] | 1 | Ensure a support role has been created to manage incidents with AWS Support |
| 1.21 | [ ] | [ ] | 1 | Do not setup access keys during initial user setup for all IAM users that have a console password |
| 1.22 | [?] | [ ] | 1 | Ensure IAM policies that allow full "*:*" administrative privileges are not created |

## 2 Logging

| # | Audit | Fix | Profile Level | Description |
| 2.1 | [x] | [ ] | 1 | Ensure CloudTrail is enabled in all regions |
| 2.2 | [?] | [ ] | 2 | Ensure CloudTrail log file validation is enabled |
| 2.3 | [x] | [ ] | 1 | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible |
| 2.4 | [?] | [ ] | 1 | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| 2.5 | [?] | [ ] | 1 | Ensure AWS Config is enabled in all regions |
| 2.6 | [x] | [ ] | 1 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket |
| 2.7 | [?] | [ ] | 2 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| 2.8 | [x] | [ ] | 2 | Ensure rotation for customer created CMKs is enabled |
| 2.9 | [ ] | [ ] | 2 | Ensure VPC flow logging is enabled in all VPCs |

## 3 Monitoring

| # | Audit | Fix | Profile Level | Description |
| 3.1 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for unauthorized API calls |
| 3.2 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA |
| 3.3 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for usage of "root" account |
| 3.4 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for IAM policy changes |
| 3.5 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for CloudTrail configuration changes |
| 3.6 | [?] | [ ] | 2 | Ensure a log metric filter and alarm exist for AWS Management Console authentication failures |
| 3.7 | [?] | [ ] | 2 | Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs |
| 3.8 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for S3 bucket policy changes |
| 3.9 | [?] | [ ] | 2 | Ensure a log metric filter and alarm exist for AWS Config configuration changes |
| 3.10 | [?] | [ ] | 2 | Ensure a log metric filter and alarm exist for security group changes |
| 3.11 | [?] | [ ] | 2 | Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) |
| 3.12 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for changes to network gateways |
| 3.13 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for route table changes |
| 3.14 | [?] | [ ] | 1 | Ensure a log metric filter and alarm exist for VPC changes |

## 4 Networking

| # | Audit | Fix | Profile Level | Description |
| 4.1 | [x] | [ ] | 1 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 |
| 4.2 | [x] | [ ] | 1 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 |
| 4.3 | [ ] | [ ] | 2 | Ensure the default security group of every VPC restricts all traffic |
| 4.4 | [?] | [ ] | 2 | Ensure routing tables for VPC peering are "least access" |

