"""Inference wrapper for the DGA XGBoost model trained in DGA_detector.ipynb."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer


BASE_FEATURES = [
    "len_full",
    "len_sld",
    "entropy",
    "tld_len",
    "high_risk_tld",
    "cv_ratio",
    "digit_ratio",
    "dict_match_ratio",
]
THRESHOLD = 0.50


def calculate_shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return float(-sum((count / length) * math.log2(count / length) for count in counts.values()))


def fast_vowel_consonant_ratio(value: str) -> float:
    vowels = sum(char in "aeiou" for char in value)
    consonants = sum(char.isalpha() and char not in "aeiou" for char in value)
    return float(consonants / max(vowels, 1))


def fast_dict_match_ratio(value: str, english_dict: set[str]) -> float:
    if not value:
        return 0.0
    matched = [False] * len(value)
    for length in range(4, min(len(value) + 1, 16)):
        for start in range(len(value) - length + 1):
            if value[start : start + length] in english_dict:
                for index in range(start, start + length):
                    matched[index] = True
    return float(sum(matched) / max(len(value), 1))


class DGADetector:
    """Score domains using the notebook's lexical and character n-gram contract."""

    def __init__(
        self,
        model_path: str | Path = "DGA_XGBoost.pkl",
        vectorizer: TfidfVectorizer | None = None,
        english_dict: Iterable[str] = (),
        threshold: float = THRESHOLD,
    ) -> None:
        self.model = joblib.load(model_path)
        self.vectorizer = vectorizer
        self.english_dict = {word.lower() for word in english_dict}
        self.threshold = threshold

    def transform(self, domains: Iterable[str]) -> pd.DataFrame:
        normalized = [str(domain).strip().lower() for domain in domains]
        slds = [domain.split(".")[0] if "." in domain else domain for domain in normalized]
        rows = []
        for domain, sld in zip(normalized, slds):
            rows.append(
                {
                    "len_full": len(domain),
                    "len_sld": len(sld),
                    "entropy": calculate_shannon_entropy(sld),
                    "tld_len": len(domain.split(".")[-1]) if "." in domain else 0,
                    "high_risk_tld": int(domain.endswith((".cc", ".ru", ".biz", ".info", ".top", ".ddns.net", ".xyz", ".ws"))),
                    "cv_ratio": fast_vowel_consonant_ratio(sld),
                    "digit_ratio": sum(char.isdigit() for char in sld) / max(len(sld), 1),
                    "dict_match_ratio": fast_dict_match_ratio(sld, self.english_dict),
                }
            )
        features = pd.DataFrame(rows, columns=BASE_FEATURES)
        if self.vectorizer is None:
            raise RuntimeError(
                "The DGA notebook saved the classifier but not its fitted TfidfVectorizer. "
                "Provide the training-time vectorizer before inference."
            )
        ngrams = self.vectorizer.transform(slds).toarray()
        ngram_columns = [f"ngram_{name}" for name in self.vectorizer.get_feature_names_out()]
        return pd.concat([features, pd.DataFrame(ngrams, columns=ngram_columns)], axis=1)

    def predict(self, domain: str) -> tuple[int, float, dict[str, object]]:
        features = self.transform([domain])
        confidence = float(self.model.predict_proba(features)[0][1])
        alert = int(confidence >= self.threshold)
        return alert, confidence, {
            "domain": domain,
            "threshold": self.threshold,
            "prediction": "DGA (1)" if alert else "Benign (0)",
        }