import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from config import (
    BUCKET_NAME,
    FEATURES_PREFIX,
    MODELS_PREFIX,
    ANOMALY_SCORE_THRESHOLD,
)

s3 = boto3.client("s3")

SYNTHETIC_USERS = {"alice", "bob", "carol", "dave", "eve"}

FEATURE_COLUMNS = [
    "hour_of_day",
    "is_business_hours",
    "read_only",
    "has_error",
    "is_sensitive",
    "ip_is_known",
    "hour_is_typical",
    "api_is_typical",
    "region_is_typical",
    "baseline_violations",
    "events_last_5min",
    "events_last_1hour",
]


def load_features():
    key = f"{FEATURES_PREFIX}/features.parquet"
    body = s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read()
    return pd.read_parquet(io.BytesIO(body))


def time_split(df, train_days=50):
    cutoff = df["event_time"].min() + pd.Timedelta(days=train_days)
    train = df[df["event_time"] < cutoff].copy()
    test = df[df["event_time"] >= cutoff].copy()
    return train, test


def diagnose_scores(scores, y_true):
    print("\n--- Anomaly score diagnostic ---")
    print(f"Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"Score mean:  {scores.mean():.4f}    Score std: {scores.std():.4f}")
    print(f"\nPercentiles:")
    for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"  p{p:>2}: {np.percentile(scores, p):.4f}")

    anomaly_scores = scores[y_true == 1]
    normal_scores = scores[y_true == 0]
    print(f"\nScore distribution by class:")
    print(f"  Normal  (n={len(normal_scores)}):  mean={normal_scores.mean():.4f}, "
          f"min={normal_scores.min():.4f}, p5={np.percentile(normal_scores, 5):.4f}")
    print(f"  Anomaly (n={len(anomaly_scores)}): mean={anomaly_scores.mean():.4f}, "
          f"max={anomaly_scores.max():.4f}, p95={np.percentile(anomaly_scores, 95):.4f}")


def sweep_thresholds(scores, y_true):
    print("\n--- Threshold sweep ---")
    print(f"{'threshold':>10}  {'flagged':>7}  {'TP':>4}  {'FP':>4}  {'FN':>4}  "
          f"{'precision':>9}  {'recall':>6}  {'f1':>5}")
    candidates = sorted({
        float(np.percentile(scores, p)) for p in [0.5, 1, 2, 5, 10, 15, 20]
    })
    for thr in candidates:
        pred = (scores < thr).astype(int)
        tp = int(((pred == 1) & (y_true == 1)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        print(f"{thr:>10.4f}  {tp+fp:>7}  {tp:>4}  {fp:>4}  {fn:>4}  "
              f"{precision:>9.3f}  {recall:>6.3f}  {f1:>5.3f}")


def evaluate(model, test_df):
    X_test = test_df[FEATURE_COLUMNS]
    scores = model.decision_function(X_test)
    y_true = test_df["is_anomaly"].to_numpy()

    diagnose_scores(scores, y_true)
    sweep_thresholds(scores, y_true)

    print("\n--- Using model's built-in threshold (predict()) ---")
    builtin_pred = (model.predict(X_test) == -1).astype(int)
    print(f"Flagged: {builtin_pred.sum()}")
    print("Confusion matrix [rows=actual, cols=predicted]:")
    print(confusion_matrix(y_true, builtin_pred))
    print(classification_report(y_true, builtin_pred, target_names=["normal", "anomaly"],
                                digits=3, zero_division=0))

    print(f"\n--- Using ANOMALY_SCORE_THRESHOLD = {ANOMALY_SCORE_THRESHOLD} from config.py ---")
    config_pred = (scores < ANOMALY_SCORE_THRESHOLD).astype(int)
    print(f"Flagged: {config_pred.sum()}")
    print("Confusion matrix:")
    print(confusion_matrix(y_true, config_pred))
    print(classification_report(y_true, config_pred, target_names=["normal", "anomaly"],
                                digits=3, zero_division=0))

    test_df = test_df.copy()
    test_df["anomaly_score"] = scores
    return test_df


def save_model(model):
    buffer = io.BytesIO()
    joblib.dump(model, buffer)
    buffer.seek(0)
    key = f"{MODELS_PREFIX}/isolation_forest.joblib"
    s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=buffer.getvalue())
    print(f"\nModel saved → s3://{BUCKET_NAME}/{key}")


def main():
    print("Loading features from S3...")
    df = load_features()
    print(f"Loaded {len(df)} events with {df.shape[1]} columns")

    before = len(df)
    df = df[df["user_name"].isin(SYNTHETIC_USERS)].reset_index(drop=True)
    print(f"Filtered to synthetic users: kept {len(df)}/{before} events")

    train_df, test_df = time_split(df)
    print(f"Train: {len(train_df)} events (baseline) | Test: {len(test_df)} events (eval window)")

    train_normal = train_df[train_df["is_anomaly"] == 0]
    print(f"Training on {len(train_normal)} clean baseline events")

    X_train = train_normal[FEATURE_COLUMNS]
    model = IsolationForest(
        n_estimators=500,
        contamination=0.05,
        max_samples=256,
        random_state=42,
        n_jobs=-1,
    )
    print("Fitting IsolationForest...")
    model.fit(X_train)

    evaluate(model, test_df)
    save_model(model)


if __name__ == "__main__":
    main()
