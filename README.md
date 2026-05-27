# Threat Hunter

An AI-powered AWS security analyst. Detects anomalous CloudTrail activity with an ML model, then has a Claude agent autonomously investigate each anomaly using a set of tools and write a human-readable incident report.

Built as the affordable, open-architecture alternative to enterprise tools like CrowdStrike or Splunk Enterprise Security, which cost $200K-$500K/year for the same core function.

---

## The problem

AWS CloudTrail records every API call made in an account — who, when, from where, whether it succeeded. A typical company produces thousands of these per day. When credentials get stolen (phishing, leaked `.env`, public S3), the evidence of the attack is in those logs from the first minute. But no one is reading them, because reading thousands of logs per day and knowing which ones are suspicious is not something humans scale to.

The expensive products solve the *detection* half well. Where security analysts actually spend their time — investigating each alert, deciding whether it's real, writing it up for action — is exactly where an LLM with the right tools can help.

---

## Architecture

```
                CloudTrail logs (S3)
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
    Feature engineering    EventBridge rule
    (batch / nightly)      (realtime pattern match)
            │                     │
            ▼                     ▼
    IsolationForest               SQS queue
    anomaly score                 │
            │                     ▼
            └──────────►   Anthropic agent (Claude Sonnet 4.6)
                                  │
                          ┌───────┼────────────────┐
                          ▼       ▼        ▼       ▼
                       baseline  threat  deploy   write
                       lookup    intel   events   report
                                                   │
                                                   ▼
                                       S3 (Markdown)
                                       SNS → email alert
```

Two complementary detection layers feed one agent:

- **Batch (ML).** IsolationForest scores every event in the historical log against per-user behavioral baselines + burst rate features. F1 = 0.964 on the planted-attack test set.
- **Realtime (rules).** An EventBridge rule pattern-matches CloudTrail events for known-suspicious patterns (sensitive IAM mutations, CloudTrail tampering, AccessDenied errors) and pushes them to SQS within seconds.

The agent doesn't care which layer raised the alert. It runs the same investigation procedure for either: pull the user's baseline → check the IP against threat intel → check for nearby deployments → write a Markdown report → publish a summary to SNS (which emails an analyst on HIGH/CRITICAL).

---

## Results

| Metric | Value |
|---|---|
| Test events | 3,555 |
| Planted attack events | 555 |
| True positives | 525 |
| False positives | 9 |
| **Precision** | **0.983** |
| **Recall** | **0.946** |
| **F1** | **0.964** |
| Agent investigation latency | 5-10 seconds |
| Agent investigation cost | ~$0.05 per event (Claude Sonnet 4.6) |

Validated across recon / failed escalation / successful escalation / exfiltration / benign-baseline scenarios. The agent correctly differentiates them and labels a benign event as "Likely False Positive — LOW severity" rather than alerting on it.

---

## How to run

### Prerequisites

- AWS account with credentials configured (`aws configure`)
- Anthropic API key with credit
- Python 3.11

### Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# .env file with:
#   ANTHROPIC_API_KEY=sk-ant-api03-...
#   ALERT_EMAIL=you@example.com

python setup_aws.py                       # bucket, trail, IAM role
python data/generate_logs.py              # synthetic CloudTrail (skip in real prod)
python data/feature_engineering.py        # → features.parquet
python training/train.py                  # → isolation_forest.joblib
python agent/bootstrap_data.py            # baselines + threat intel seed
python routing/eventbridge_setup.py       # SQS + EventBridge rule
python routing/notifications_setup.py     # SNS email (confirm via inbox)
```

### Run an investigation

Batch mode (pick an event from the parquet, investigate it):
```bash
python agent/run_agent.py
```

Validation across all attack types:
```bash
python agent/test_scenarios.py
```

Realtime mode (blocks on SQS):
```bash
python routing/process_queue.py
# In another terminal, trigger an event:
aws iam create-access-key --user-name nonexistent-victim
```

---

## What's real, what's synthetic

This is a proof of concept. Being explicit about which parts are which:

| Component | Status |
|---|---|
| CloudTrail logs flowing through AWS | Real |
| EventBridge rule + SQS queue + agent consumer | Real |
| Claude-driven investigation reasoning | Real (Anthropic API, paid tokens) |
| SNS email alerts | Real |
| Per-user behavioral baselines (alice, bob, carol, …) | Synthetic, generated by `data/generate_logs.py` |
| Threat intelligence feed | Stubbed with one entry (the synthetic attacker IP) |
| Deployment event history | Stubbed with 5 plausible entries |
| IsolationForest model | Trained on synthetic data; technique transfers to real CloudTrail without changes |

To productionize, the synthetic pieces would each be replaced by real data sources: per-user baselines from actual CloudTrail history, threat intel from AbuseIPDB / GreyNoise, deployment events from CodeDeploy / GitHub Actions.

---

## Cost

| Service | Usage in this project | Cost |
|---|---|---|
| S3 | ~50 MB logs + features + reports | < $0.01/mo |
| Lambda | None deployed | $0 |
| EventBridge | CloudTrail-sourced events are free | $0 |
| SQS | Well under free tier (1M req/mo) | $0 |
| SNS email | Well under free tier (1K/mo) | $0 |
| CloudTrail | Management events are free | $0 |
| **Anthropic Claude Sonnet 4.6** | ~$0.05 per investigation | Variable |

At 100 investigations/day in production: **~$150/month**. Compare CrowdStrike at $25K+/month for an organization of that size.

---

## What I'd do next (production gaps)

The architectural pattern is proven end-to-end. To take it from working POC to real production:

- **Realtime ML scoring path** — current realtime path uses EventBridge pattern rules only. Adding ML scoring to the realtime path needs a Lambda with sklearn + a DynamoDB table for per-user state (rolling burst counters).
- **Real CloudTrail-derived baselines** — current baselines come from synthetic data; the production version would compute baselines from the most recent 30-90 days of actual CloudTrail history per IAM identity.
- **Prompt injection hardening** — CloudTrail fields like `userAgent` can contain attacker-controlled text. Tools should sanitize/escape user-provided strings before they reach the model context.
- **Retraining pipeline** — `pipelines/pipeline.py` is a stub. A real version would be a SageMaker Pipeline on a weekly schedule with model-registry promotion.
- **Drift monitoring** — `monitoring/setup_monitor.py` is a stub. SageMaker Model Monitor would track feature distributions and alert when production drifts from training.
- **Integration tests + agent eval set** — none exist. The first thing I'd build before deploying.
- **Multi-event correlation** — currently each alert is investigated in isolation. A correlation layer that recognizes "these 50 events are one attack" would compress alert volume and improve the report.

---

## File map

```
threat-hunter/
├── config.py                        # all settings, env loading
├── setup_aws.py                     # bucket, trail, IAM role
├── data/
│   ├── generate_logs.py             # synthetic CloudTrail
│   ├── feature_engineering.py       # parquet of engineered features
│   └── inspect.py                   # CSV export for browsing
├── training/
│   └── train.py                     # IsolationForest + diagnostics
├── agent/
│   ├── tools.py                     # 4 investigation tools (pure Python)
│   ├── run_agent.py                 # agent loop using Anthropic SDK
│   ├── test_scenarios.py            # validation across 5 attack types
│   ├── bootstrap_data.py            # seed baselines + threat intel
│   └── lambda_tools/                # Bedrock-Agent-format wrappers (unused for now)
├── routing/
│   ├── eventbridge_setup.py         # SQS + EventBridge rule
│   ├── process_queue.py             # local consumer that invokes the agent
│   └── notifications_setup.py       # SNS topic + email subscription
├── pipelines/                       # (stub)
└── monitoring/                      # (stub)
```