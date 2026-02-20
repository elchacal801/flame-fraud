# Baseline: Commercial Wire Velocity

```yaml
---
id: BASE-001
title: "Commercial Wire Velocity Baseline"
category: Baseline
date: 2026-02-20
author: "FLAME Project"
tags:
  - b2b-payments
  - wire-transfer
  - commercial-banking
---
```

## Description

This baseline document defines the "normal" operating parameters for commercial wire transfers within the SME (Small to Medium Enterprise) banking sector, used to contextualize detection rules for TP-0002 (BEC), TP-0019 (Business Identity Theft), and TP-0020 (Supply Chain Payment Fraud).

## Normal Patterns

* **Approval Latency:** The average time between wire initiation and secondary approval is typically **2-4 hours** during business days. Approvals executed within < 10 seconds of initiation represent high anomalous velocity (indicative of ATO or collusive insider).
* **Beneficiary Novelty:** For established businesses (> 1 year old), **85%** of weekly outbound wire volume is directed to existing, historical beneficiaries.
* **Volume Spikes:** Normal accounts exhibit a standard deviation of no more than **200%** week-over-week in total outbound volume, unless preceded by a corresponding inbound funding event.

## Application to Detection

Detection rules should use these baselines to set thresholds. For instance, a rule looking for "abnormal volume" should trigger at >3 standard deviations (or >300% WoW increase) to drastically reduce false positives.
