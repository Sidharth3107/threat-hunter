import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
import pandas as pd

from agent.run_agent import investigate
from config import BUCKET_NAME, FEATURES_PREFIX

s3 = boto3.client("s3")


def load_features():
    body = s3.get_object(Bucket=BUCKET_NAME, Key=f"{FEATURES_PREFIX}/features.parquet")["Body"].read()
    return pd.read_parquet(io.BytesIO(body))


def pick_scenarios(df):
    attacks = df[df["is_anomaly"] == 1]
    normals = df[(df["is_anomaly"] == 0) & (df["user_name"] == "alice")]

    scenarios = {}

    recon = attacks[
        (attacks["has_error"] == 0)
        & (attacks["is_sensitive"] == 0)
        & (attacks["region"] == "us-east-1")
        & (attacks["hour_of_day"] == 2)
    ]
    if len(recon):
        scenarios["RECON (read-only @ 2 AM from attacker IP)"] = recon.iloc[0]

    failed_esc = attacks[(attacks["has_error"] == 1) & (attacks["is_sensitive"] == 1)]
    if len(failed_esc):
        scenarios["FAILED ESCALATION (AccessDenied on sensitive API)"] = failed_esc.iloc[0]

    succ_esc = attacks[(attacks["has_error"] == 0) & (attacks["is_sensitive"] == 1)]
    if len(succ_esc):
        scenarios["SUCCESSFUL ESCALATION (IAM mutation succeeded)"] = succ_esc.iloc[0]

    exfil = attacks[(attacks["region"] == "eu-west-1")]
    if len(exfil):
        scenarios["EXFILTRATION (mass GetObject from foreign region)"] = exfil.iloc[0]

    if len(normals):
        scenarios["BENIGN BASELINE (normal alice activity, control)"] = normals.iloc[0]

    return scenarios


def main():
    print("Loading features and selecting one event per attack phase...\n")
    df = load_features()
    scenarios = pick_scenarios(df)
    print(f"Selected {len(scenarios)} scenarios\n")

    results = []
    total_in = 0
    total_out = 0

    for i, (label, event) in enumerate(scenarios.items(), 1):
        print("=" * 80)
        print(f"SCENARIO {i}/{len(scenarios)}: {label}")
        print(f"  event_time : {event['event_time']}")
        print(f"  source_ip  : {event['source_ip']}")
        print(f"  event_name : {event['event_name']}")
        print(f"  violations : {event['baseline_violations']}, "
              f"sensitive={bool(event['is_sensitive'])}, "
              f"error={bool(event['has_error'])}")
        print("=" * 80)

        result = investigate(event.to_dict(), verbose=False)

        report = result.get("final_report") or {}
        severity = (report.get("severity") or "no-report").upper()
        title = report.get("title") or "(no report written)"
        uri = report.get("s3_uri") or "n/a"

        print(f"\n  → severity: {severity}")
        print(f"  → title:    {title}")
        print(f"  → s3:       {uri}")
        print(f"  → tokens:   in={result['input_tokens']}, out={result['output_tokens']}, "
              f"turns={result['turns']}\n")

        total_in += result["input_tokens"]
        total_out += result["output_tokens"]
        results.append({
            "scenario": label,
            "severity": severity,
            "title": title,
            "s3_uri": uri,
            "turns": result["turns"],
        })

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    for r in results:
        print(f"  [{r['severity']:>8}]  {r['scenario']}")
        print(f"               {r['title']}")
        print()

    cost = (total_in * 3 + total_out * 15) / 1_000_000
    print(f"Total tokens — input: {total_in}, output: {total_out}")
    print(f"Total estimated cost: ${cost:.4f}")


if __name__ == "__main__":
    main()