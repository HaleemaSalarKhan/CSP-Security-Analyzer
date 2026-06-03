"""Training helpers for the CSP Random Forest model."""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from .csp_features import FEATURE_COLUMNS


def balance_classes(df: pd.DataFrame, label_col: str = "label", random_state: int = 42) -> pd.DataFrame:
    """Balance labels by oversampling minority classes."""
    groups = [group for _, group in df.groupby(label_col)]
    if not groups:
        return df

    max_size = max(len(group) for group in groups)
    balanced = [
        group.sample(max_size, replace=len(group) < max_size, random_state=random_state)
        for group in groups
    ]
    return pd.concat(balanced).sample(frac=1, random_state=random_state).reset_index(drop=True)


def train_random_forest(
    df: pd.DataFrame,
    model_path: str | Path,
    random_state: int = 42,
) -> Tuple[RandomForestClassifier, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Train and save a RandomForestClassifier."""
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=random_state,
        stratify=stratify,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        random_state=random_state,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    return model, X_train, X_test, y_train, y_test
