"""Threat-scoring classifier.

A standardised logistic regression is used on purpose: it is a calibrated
probabilistic classifier whose per-feature contribution to the log-odds is
*exact* (coefficient x standardised value), which makes the Explainable-AI
layer faithful to the model rather than a post-hoc approximation.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_NAMES
from .synthetic import build_dataset


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


@dataclass
class Decomposition:
    probability: float
    logit: float
    intercept: float
    baseline_probability: float
    contributions: list[float]  # log-odds contribution per feature
    standardised: list[float]


class ThreatModel:
    def __init__(self, seed: int = 42, n_per_class: int = 10000) -> None:
        self.seed = seed
        self.n_per_class = n_per_class
        self.scaler = StandardScaler()
        self.clf = LogisticRegression(C=0.3, class_weight="balanced", max_iter=3000, random_state=seed)
        self.metrics: dict[str, float] = {}
        self.trained = False

    def train(self) -> dict[str, float]:
        X, y = build_dataset(self.n_per_class, self.seed)
        X_arr, y_arr = np.asarray(X, dtype=float), np.asarray(y)

        # Held-out evaluation for the reported metrics ...
        X_tr, X_te, y_tr, y_te = train_test_split(
            X_arr, y_arr, test_size=0.2, stratify=y_arr, random_state=self.seed)
        eval_scaler = StandardScaler().fit(X_tr)
        eval_clf = LogisticRegression(C=0.3, class_weight="balanced", max_iter=3000,
                                      random_state=self.seed).fit(eval_scaler.transform(X_tr), y_tr)
        proba = eval_clf.predict_proba(eval_scaler.transform(X_te))[:, 1]
        pred = (proba >= 0.5).astype(int)
        self.metrics = {
            "samples": int(len(y_arr)),
            "accuracy": round(float(accuracy_score(y_te, pred)), 4),
            "precision": round(float(precision_score(y_te, pred)), 4),
            "recall": round(float(recall_score(y_te, pred)), 4),
            "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
        }

        # ... then refit on everything for the deployed model.
        self.scaler.fit(X_arr)
        self.clf.fit(self.scaler.transform(X_arr), y_arr)
        self.trained = True
        return self.metrics

    def decompose(self, vector: list[float]) -> Decomposition:
        if not self.trained:
            raise RuntimeError("Model has not been trained")
        z = self.scaler.transform(np.asarray([vector], dtype=float))[0]
        coefs = self.clf.coef_[0]
        contributions = (coefs * z).tolist()
        intercept = float(self.clf.intercept_[0])
        logit = intercept + float(sum(contributions))
        return Decomposition(
            probability=sigmoid(logit),
            logit=logit,
            intercept=intercept,
            baseline_probability=sigmoid(intercept),
            contributions=contributions,
            standardised=z.tolist(),
        )

    def coefficients(self) -> dict[str, float]:
        return {n: round(float(c), 4) for n, c in zip(FEATURE_NAMES, self.clf.coef_[0])}
