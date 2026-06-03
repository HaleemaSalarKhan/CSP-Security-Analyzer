from __future__ import annotations

from pathlib import Path
import sys

import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.csp_features import FEATURE_COLUMNS, extract_csp_features, label_csp
from src.model_utils import balance_classes, train_random_forest

DATA_DIR = PROJECT_ROOT / "data"
MODEL_DIR = PROJECT_ROOT / "models"
FIGURE_DIR = PROJECT_ROOT / "reports" / "figures"


def build_policy(
    unsafe_inline: bool,
    unsafe_eval: bool,
    wildcard: bool,
    http: bool,
    nonce: bool,
    strict_dynamic: bool,
    sha256: bool,
    extra_scheme: str,
) -> str:
    default_sources = ["'self'"]
    script_sources = ["'self'"]
    img_sources = ["'self'", "https:"]
    connect_sources = ["'self'", "https:"]

    if wildcard:
        default_sources.append("*")
        img_sources.append("*")
    if http:
        default_sources.append("http:")
        img_sources.append("http:")
    if unsafe_inline:
        script_sources.append("'unsafe-inline'")
    if unsafe_eval:
        script_sources.append("'unsafe-eval'")
    if nonce:
        script_sources.append("'nonce-abc123'")
    if strict_dynamic:
        script_sources.append("'strict-dynamic'")
    if sha256:
        script_sources.append("'sha256-AbCdEf123456='")
    if extra_scheme == "data":
        img_sources.append("data:")
    if extra_scheme == "blob":
        script_sources.append("blob:")
    if extra_scheme == "wss":
        connect_sources.append("wss:")

    return (
        f"default-src {' '.join(default_sources)}; "
        f"script-src {' '.join(script_sources)}; "
        f"img-src {' '.join(img_sources)}; "
        f"connect-src {' '.join(connect_sources)}; "
        "object-src 'none'; base-uri 'self'"
    )


def generate_starter_rows() -> list[dict]:
    rows = []
    extras = ["none", "data", "blob", "wss"]
    index = 1

    for unsafe_inline in [False, True]:
        for unsafe_eval in [False, True]:
            for wildcard in [False, True]:
                for http in [False, True]:
                    for nonce in [False, True]:
                        for strict_dynamic in [False, True]:
                            sha256 = index % 3 == 0
                            extra_scheme = extras[index % len(extras)]
                            policy = build_policy(
                                unsafe_inline,
                                unsafe_eval,
                                wildcard,
                                http,
                                nonce,
                                strict_dynamic,
                                sha256,
                                extra_scheme,
                            )
                            _, label = label_csp(policy)
                            rows.append(
                                {
                                    "domain": f"{label.lower()}-starter-{index:03d}.example",
                                    "csp_header": policy,
                                }
                            )
                            index += 1

    return rows


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    MODEL_DIR.mkdir(exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)

    dataset_rows = []
    for row in generate_starter_rows():
        dataset_rows.append(
            {
                "domain": row["domain"],
                "csp_header": row["csp_header"],
                "report_only_header": "",
                "status_code": 200,
                "has_csp": 1,
            }
        )

    dataset = pd.DataFrame(dataset_rows)
    dataset.to_csv(DATA_DIR / "csp_dataset.csv", index=False)

    features = dataset["csp_header"].apply(extract_csp_features).apply(pd.Series)
    scores_labels = dataset["csp_header"].apply(label_csp)

    labeled = pd.concat([dataset, features], axis=1)
    labeled["security_score"] = scores_labels.apply(lambda value: value[0])
    labeled["label"] = scores_labels.apply(lambda value: value[1])
    balanced = balance_classes(labeled, label_col="label")
    balanced.to_csv(DATA_DIR / "csp_features_labeled.csv", index=False)

    model, _, X_test, _, y_test = train_random_forest(
        balanced,
        MODEL_DIR / "csp_random_forest.pkl",
        random_state=42,
    )

    labels = ["Weak", "Medium", "Strong"]
    predictions = model.predict(X_test)
    cm = confusion_matrix(y_test, predictions, labels=labels)

    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    importance = pd.DataFrame(
        {"feature": FEATURE_COLUMNS, "importance": model.feature_importances_}
    ).sort_values("importance", ascending=False)
    plt.figure(figsize=(8, 5))
    sns.barplot(data=importance, x="importance", y="feature", color="#2f6f8f")
    plt.title("Feature Importance")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "feature_importance.png", dpi=150)
    plt.close()

    plt.figure(figsize=(6, 4))
    sns.countplot(data=balanced, x="label", order=labels, hue="label", legend=False)
    plt.title("Label Distribution")
    plt.xlabel("CSP Security Label")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "label_distribution.png", dpi=150)
    plt.close()

    joblib.load(MODEL_DIR / "csp_random_forest.pkl")
    print("Starter dataset, labeled features, model, and figures generated.")


if __name__ == "__main__":
    main()
