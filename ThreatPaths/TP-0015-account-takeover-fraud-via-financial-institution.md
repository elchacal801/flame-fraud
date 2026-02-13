# TP-0015: Account Takeover Fraud via Financial Institution Impersonation

```yaml
---
id: TP-0015
title: Account Takeover Fraud via Financial Institution Impersonation
category: ThreatPath
date: 2026-02-13
author: elchacal801
source: https://www.ic3.gov/PSA/2025/PSA251125
tlp: WHITE
sector: 
  - banking
  - cross-sector
fraud_types: 
  - account-takeover
  - social-engineering
  - vishing
  - phishing
  - smishing
cfpf_phases: 
  - P1
  - P2
  - P3
  - P4
  - P5
mitre_attack: 
  - T1566.001
  - T1566.002
  - T1566.003
  - T1078
ft3_tactics: []
mitre_f3: []
groupib_stages:
  - Trust Abuse
  - End-user Interaction
  - Credential Access
  - Account Access
  - Perform Fraud
  - Monetization
tags:
  - financial-impersonation
  - multi-factor-authentication-bypass
  - seo-poisoning
  - phishing-domains
  - wire-fraud
  - cryptocurrency
---
```

## Summary

This threat path documents account takeover (ATO) fraud schemes where threat actors impersonate financial institution staff or websites to gain unauthorized access to victims' financial accounts. Targeting individuals, businesses, and organizations across sectors, actors use social engineering techniques and fraudulent websites to obtain login credentials, including multi-factor authentication (MFA) codes. Once access is obtained, actors quickly transfer funds to criminal-controlled accounts, often linked to cryptocurrency wallets, and may lock victims out of their accounts by changing passwords. According to FBI IC3 data, over 5,100 complaints of ATO fraud were reported from January 2025, with losses exceeding $262 million.

## Threat Path Hypothesis

With **high confidence**, we assess that attackers are systematically targeting financial account holders through a combination of social engineering and technical deception. The threat path follows this sequence:

1. Threat actors conduct reconnaissance to identify potential targets and gather information to make their impersonation more convincing.
2. Actors establish attack infrastructure, including phishing websites and SEO-poisoned search results.
3. Initial contact is made via text messages, phone calls, or emails, impersonating financial institution staff or creating a sense of urgency about fraudulent transactions.
4. Victims are manipulated into providing login credentials and MFA codes, or directed to convincing phishing sites.
5. Once credentials are obtained, actors access legitimate financial platforms and may modify account settings to maintain control.
6. Funds are rapidly transferred to criminal-controlled accounts, often linked to cryptocurrency wallets for quick conversion.

## CFPF Phase Mapping

### Phase 1: Reconnaissance

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P1-002: SEO poisoning | Manipulation of search engine results via purchased ads that imitate legitimate financial institutions to direct victims to phishing sites | Financial institution keyword targeting; Ads mimicking official financial institution ads; Prominence in search results |
| CFPF-P1-003: Lookalike domain registration | Registration of domains that visually resemble legitimate financial institution domains | Domains mimicking banking websites; Similar visual design elements; Minor spelling variations in URLs |
| Social media reconnaissance | Collecting personal information from victims' social media accounts to craft convincing impersonations or guess security question answers | Publicly shared information about pets, schools, family members, or birthdays used in attacks |

### Phase 2: Initial Access

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P2-001: Credential harvesting via spoofed page | Victims enter credentials on convincing replicas of financial institution login pages | Phishing domains; Similar visual elements to legitimate sites; Non-standard URLs |
| CFPF-P2-002: Vishing (voice phishing) | Phone-based social engineering where actors impersonate bank staff to extract credentials or MFA codes | Unsolicited calls claiming to be from financial institutions; Requests for login information or one-time passcodes |
| CFPF-P2-003: Smishing (SMS phishing) | Fraudulent SMS messages impersonating financial institutions to direct victims to credential harvesting pages | Text messages about suspicious transactions; Links to phishing sites; Requests for account verification |
| CFPF-P2-004: Email phishing | Email campaigns impersonating financial institutions to deliver credential phishing content | Emails claiming fraudulent activity on accounts; Urgent requests to verify information; Links to phishing sites |

### Phase 3: Positioning

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P3-003: Modify contact information | Changes to email, phone, or contact information to prevent legitimate account holders from receiving alerts | Modified contact details in financial accounts; Missing notifications of account activity |
| CFPF-P3-004: Disable or redirect alerts | Modification of notification preferences to suppress transaction alerts | Disabled fraud alerts; Changed notification settings |
| Password reset manipulation | Using compromised credentials to initiate password resets and gain full control of accounts | Password reset requests not initiated by the account owner; Locked out accounts |

### Phase 4: Execution

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P4-001: Unauthorized wire transfer | Initiation of wire transfers to actor-controlled accounts using compromised access | Unexplained wire transfers; Transfers to unfamiliar accounts; Missing deposits |
| Unauthorized account access | Accessing financial accounts without permission to view sensitive information or conduct transactions | Logins from unusual locations or devices; Account activity during unusual hours |

### Phase 5: Monetization

| Technique | Description | Indicators |
|-----------|-------------|------------|
| CFPF-P5-001: Domestic wire to mule account | Wire transfer to domestic accounts controlled by money mules | Wire transfers to previously unused recipients; Rapid movement of funds |
| CFPF-P5-003: Cryptocurrency conversion | Conversion of stolen funds to cryptocurrency to obscure money trail | Transfers to accounts linked to cryptocurrency wallets; Rapid disbursement of funds |

## Look Left / Look Right

### Look Left (Earlier Activities)

The reported activity is likely preceded by:

1. **Target selection and profiling**: Actors may compile lists of potential victims, possibly from public records or purchased data.
2. **Infrastructure development**: Creating convincing phishing sites and SEO poisoning campaigns requires technical preparation.
3. **Research on financial institutions**: Actors study the legitimate procedures, communication styles, and security measures of targeted financial institutions to create convincing impersonations.

### Look Right (Subsequent Activities)

Following successful account takeover, actors likely:

1. **Layer transactions**: Use multiple accounts or platforms to obscure the money trail.
2. **Convert to cryptocurrency**: Rapidly move funds to cryptocurrency wallets for anonymity.
3. **Cash out**: Convert cryptocurrency to fiat currency through exchanges with minimal KYC/AML controls.
4. **Target additional victims**: Reinvest proceeds into expanding operations to target more victims.

## Controls & Mitigations

1. **User Education and Awareness**
   - Train users to verify the authenticity of financial institution communications
   - Educate users never to share MFA codes or passwords with anyone, including those claiming to be from their financial institution
   - Encourage the use of bookmarks rather than search engine results to access financial websites

2. **Technical Controls**
   - Implement strong multi-factor authentication that cannot be easily bypassed through social engineering
   - Deploy anti-phishing solutions that can detect and block access to known phishing sites
   - Implement account activity monitoring and anomaly detection to identify unauthorized access

3. **Process Controls**
   - Establish transaction verification procedures for high-value transfers
   - Implement cooling-off periods for adding new payment recipients or changing account settings
   - Develop rapid response protocols for suspected account takeovers

4. **Financial Institution Measures**
   - Monitor for phishing sites impersonating the institution and work with hosting providers to take them down
   - Implement advanced fraud detection systems to identify suspicious login attempts and transactions
   - Clearly communicate to customers how the institution will and will not contact them

## Detection Approaches

### Account Activity Monitoring

```sql
-- Detect suspicious login and password reset activities
SELECT user_id, COUNT(DISTINCT ip_address) as ip_count, 
       COUNT(DISTINCT device_id) as device_count,
       COUNT(CASE WHEN action_type = 'password_reset' THEN 1 END) as password_resets,
       COUNT(*) as total_actions
FROM user_activities
WHERE timestamp >= NOW() - INTERVAL 24 HOUR
GROUP BY user_id
HAVING ip_count > 2 OR device_count > 2 OR password_resets >= 1
```

### Transaction Monitoring

```sql
-- Detect first-time high-value transfers to new recipients
SELECT a.account_id, a.customer_id, t.transaction_id, t.amount, 
       t.recipient_account, t.timestamp
FROM transactions t
JOIN accounts a ON t.account_id = a.account_id
LEFT JOIN transactions prev ON t.recipient_account = prev.recipient_account
  AND prev.timestamp < t.timestamp
  AND t.account_id = prev.account_id
WHERE t.transaction_type IN ('wire', 'ach')
  AND t.amount > 5000
  AND prev.transaction_id IS NULL
  AND t.timestamp >= NOW() - INTERVAL 7 DAY
```

### Authentication Anomalies

```splunk
index=auth sourcetype=authentication user=* 
| stats count as auth_attempts, values(src_ip) as src_ips, values(user_agent) as user_agents, values(auth_method) as auth_methods by user, date_hour 
| where mvcount(src_ips) > 2 OR mvcount(user_agents) > 2 
| sort -auth_attempts
```

### Contact Information Changes

```sql
-- Detect changes to contact information followed by financial transactions
SELECT u.user_id, c.change_type, c.changed_at, t.transaction_id, 
       t.amount, t.transaction_type, t.recipient
FROM contact_info_changes c
JOIN users u ON c.user_id = u.user_id
JOIN transactions t ON t.user_id = u.user_id
WHERE c.change_type IN ('email', 'phone', 'address')
  AND t.timestamp BETWEEN c.changed_at AND c.changed_at + INTERVAL 72 HOUR
  AND t.amount > 1000
ORDER BY c.changed_at
```

## References

1. FBI Internet Crime Complaint Center (IC3) PSA2025125 - Account Takeover Fraud via Impersonation of Financial Institution Support - https://www.ic3.gov/PSA/2025/PSA251125

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-13 | elchacal801 | Initial creation |
