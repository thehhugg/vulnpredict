"""Unit tests for the ML pipeline: feature extraction, training, and prediction.

Covers vulnpredict.ml — extract_features, train_model, load_model, predict.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from vulnpredict.ml import extract_features, load_model, predict, train_model


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(**overrides: Any) -> Dict[str, Any]:
    """Create a minimal function_analysis finding with sensible defaults."""
    base: Dict[str, Any] = {
        "type": "function_analysis",
        "name": "test_func",
        "length": 10,
        "dangerous_calls": [],
        "cyclomatic_complexity": 3,
        "max_nesting_depth": 2,
        "input_validation": [],
        "sensitive_data_involved": False,
        "num_sensitive_vars": 0,
        "commit_count": 5,
        "unique_authors": 2,
        "last_modified_days": 30,
    }
    base.update(overrides)
    return base


def _make_taint_finding(**overrides: Any) -> Dict[str, Any]:
    """Create a taint_analysis finding."""
    base: Dict[str, Any] = {
        "type": "taint_analysis",
        "source": [("input", 1)],
        "sink": "eval",
        "sink_line": 10,
        "variable": "user_input",
        "trace": [("input", 1), ("eval", 10)],
    }
    base.update(overrides)
    return base


def _make_interproc_finding(**overrides: Any) -> Dict[str, Any]:
    """Create an interprocedural_taint finding."""
    base: Dict[str, Any] = {
        "type": "interprocedural_taint",
        "source_func": "module::get_input",
        "sink_func": "module::run_query",
        "sink": "execute",
        "sink_line": 42,
        "call_chain": ["module::get_input", "module::process", "module::run_query"],
        "tainted_var": "query",
        "var_trace": [{"user_input"}, {"query"}],
    }
    base.update(overrides)
    return base


def _make_dependency_finding(**overrides: Any) -> Dict[str, Any]:
    """Create a dependencies finding."""
    base: Dict[str, Any] = {
        "type": "dependencies",
        "dependencies": [
            {"name": "requests", "version": "2.28.0", "vulnerable": True},
            {"name": "flask", "version": "2.3.0", "vulnerable": False},
        ],
        "num_vulnerable_dependencies": 1,
        "num_outdated_dependencies": 0,
        "max_dependency_severity": 0,
    }
    base.update(overrides)
    return base


@pytest.fixture
def sample_findings() -> List[Dict[str, Any]]:
    """A mixed list of findings for feature extraction tests."""
    return [
        _make_finding(dangerous_calls=["eval"], cyclomatic_complexity=15),
        _make_finding(length=100, max_nesting_depth=8),
        _make_taint_finding(),
        _make_interproc_finding(),
        _make_dependency_finding(),
        _make_finding(
            embedding=[0.1, 0.2, 0.3, 0.4],
            sensitive_data_involved=True,
            num_sensitive_vars=3,
        ),
    ]


@pytest.fixture
def trained_model_path(sample_findings: List[Dict[str, Any]]) -> str:
    """Train a model and return the path to the saved joblib file."""
    features = extract_features(sample_findings)
    labels = pd.Series([1, 0, 1, 1, 0, 0])
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
        model_path = f.name
    try:
        train_model(features, labels, model_path=model_path)
        yield model_path  # type: ignore[misc]
    finally:
        if os.path.exists(model_path):
            os.unlink(model_path)


# ---------------------------------------------------------------------------
# extract_features tests
# ---------------------------------------------------------------------------


class TestExtractFeatures:
    """Tests for the extract_features function."""

    def test_returns_dataframe(self, sample_findings: List[Dict[str, Any]]) -> None:
        """extract_features should return a pandas DataFrame."""
        df = extract_features(sample_findings)
        assert isinstance(df, pd.DataFrame)

    def test_correct_row_count(self, sample_findings: List[Dict[str, Any]]) -> None:
        """DataFrame should have one row per finding."""
        df = extract_features(sample_findings)
        assert len(df) == len(sample_findings)

    def test_all_numeric_columns(self, sample_findings: List[Dict[str, Any]]) -> None:
        """All columns should be numeric (no strings or objects)."""
        df = extract_features(sample_findings)
        for col in df.columns:
            assert pd.api.types.is_numeric_dtype(df[col]), f"Column {col} is not numeric"

    def test_no_nan_or_inf(self, sample_findings: List[Dict[str, Any]]) -> None:
        """DataFrame should have no NaN or infinite values."""
        df = extract_features(sample_findings)
        assert not df.isnull().any().any(), "DataFrame contains NaN values"
        assert not np.isinf(df.values).any(), "DataFrame contains infinite values"

    def test_dangerous_calls_count(self) -> None:
        """dangerous_calls should be converted to a count."""
        findings = [_make_finding(dangerous_calls=["eval", "exec"])]
        df = extract_features(findings)
        assert df["dangerous_calls"].iloc[0] == 2.0

    def test_taint_features(self) -> None:
        """Taint findings should set taint-specific features."""
        findings = [_make_taint_finding(trace=[("input", 1), ("process", 5), ("eval", 10)])]
        df = extract_features(findings)
        assert df["taint_path_to_sink"].iloc[0] == 1.0
        assert df["taint_path_length"].iloc[0] == 3.0

    def test_interprocedural_features(self) -> None:
        """Interprocedural taint findings should set call chain features."""
        findings = [_make_interproc_finding()]
        df = extract_features(findings)
        assert df["interprocedural_taint_path"].iloc[0] == 1.0
        assert df["interprocedural_call_chain_length"].iloc[0] == 3.0
        assert df["interprocedural_var_trace_length"].iloc[0] == 2.0

    def test_dependency_features(self) -> None:
        """Dependency findings should extract dependency-specific features."""
        findings = [_make_dependency_finding()]
        df = extract_features(findings)
        assert df["dependency_count"].iloc[0] == 2.0
        assert df["num_vulnerable_dependencies"].iloc[0] == 1.0

    def test_embedding_features(self) -> None:
        """Embedding vectors should be expanded into individual columns."""
        findings = [_make_finding(embedding=[0.1, 0.2, 0.3])]
        df = extract_features(findings)
        assert "embedding_0" in df.columns
        assert "embedding_1" in df.columns
        assert "embedding_2" in df.columns
        assert abs(df["embedding_0"].iloc[0] - 0.1) < 1e-6

    def test_embedding_padding(self) -> None:
        """Findings without embeddings should be padded with zeros."""
        findings = [
            _make_finding(embedding=[0.1, 0.2, 0.3]),
            _make_finding(),  # no embedding
        ]
        df = extract_features(findings)
        assert df["embedding_0"].iloc[1] == 0.0
        assert df["embedding_1"].iloc[1] == 0.0
        assert df["embedding_2"].iloc[1] == 0.0

    def test_taint_finding_count_global(self) -> None:
        """taint_finding_count should be the total count of taint findings."""
        findings = [
            _make_finding(),
            _make_taint_finding(),
            _make_taint_finding(),
        ]
        df = extract_features(findings)
        # All rows should have the same global taint count
        assert (df["taint_finding_count"] == 2.0).all()

    def test_sensitive_data_features(self) -> None:
        """Sensitive data flags should be correctly extracted."""
        findings = [_make_finding(sensitive_data_involved=True, num_sensitive_vars=5)]
        df = extract_features(findings)
        assert df["sensitive_data_involved"].iloc[0] == 1.0
        assert df["num_sensitive_vars"].iloc[0] == 5.0

    def test_code_churn_features(self) -> None:
        """Git churn features should be correctly extracted."""
        findings = [_make_finding(commit_count=42, unique_authors=7, last_modified_days=365)]
        df = extract_features(findings)
        assert df["commit_count"].iloc[0] == 42.0
        assert df["unique_authors"].iloc[0] == 7.0
        assert df["last_modified_days"].iloc[0] == 365.0

    # --- Edge cases ---

    def test_empty_findings_list(self) -> None:
        """Empty findings list should return an empty DataFrame."""
        df = extract_features([])
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0

    def test_single_finding(self) -> None:
        """A single finding should produce a 1-row DataFrame."""
        df = extract_features([_make_finding()])
        assert len(df) == 1

    def test_missing_features_default_to_zero(self) -> None:
        """Findings with missing keys should default to 0."""
        # Minimal finding with almost no keys
        findings: List[Dict[str, Any]] = [{"type": "unknown"}]
        df = extract_features(findings)
        assert len(df) == 1
        # All values should be 0 (or close to it)
        assert (df.iloc[0] == 0).all()

    def test_none_values_handled(self) -> None:
        """None values in finding fields should not cause errors."""
        findings = [_make_finding(
            cyclomatic_complexity=None,
            max_nesting_depth=None,
            commit_count=None,
        )]
        df = extract_features(findings)
        assert len(df) == 1
        assert not df.isnull().any().any()

    def test_non_numeric_embedding_values(self) -> None:
        """Non-numeric embedding values should be replaced with 0."""
        findings = [_make_finding(embedding=[0.1, "bad", None])]
        df = extract_features(findings)
        assert df["embedding_0"].iloc[0] == 0.1
        assert df["embedding_1"].iloc[0] == 0.0
        assert df["embedding_2"].iloc[0] == 0.0


# ---------------------------------------------------------------------------
# train_model tests
# ---------------------------------------------------------------------------


class TestTrainModel:
    """Tests for the train_model function."""

    def test_returns_classifier(self, sample_findings: List[Dict[str, Any]]) -> None:
        """train_model should return a RandomForestClassifier."""
        features = extract_features(sample_findings)
        labels = pd.Series([1, 0, 1, 1, 0, 0])
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            model_path = f.name
        try:
            clf = train_model(features, labels, model_path=model_path)
            assert isinstance(clf, RandomForestClassifier)
        finally:
            os.unlink(model_path)

    def test_saves_model_file(self, sample_findings: List[Dict[str, Any]]) -> None:
        """train_model should save a model file to the specified path."""
        features = extract_features(sample_findings)
        labels = pd.Series([1, 0, 1, 1, 0, 0])
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            model_path = f.name
        try:
            train_model(features, labels, model_path=model_path)
            assert os.path.exists(model_path)
            assert os.path.getsize(model_path) > 0
        finally:
            os.unlink(model_path)

    def test_small_dataset_no_crash(self) -> None:
        """Training with very few samples (< 5) should not crash."""
        findings = [_make_finding(), _make_finding(dangerous_calls=["eval"])]
        features = extract_features(findings)
        labels = pd.Series([0, 1])
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            model_path = f.name
        try:
            clf = train_model(features, labels, model_path=model_path)
            assert isinstance(clf, RandomForestClassifier)
        finally:
            os.unlink(model_path)

    def test_model_can_predict_after_training(
        self, sample_findings: List[Dict[str, Any]]
    ) -> None:
        """A freshly trained model should be able to make predictions."""
        features = extract_features(sample_findings)
        labels = pd.Series([1, 0, 1, 1, 0, 0])
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            model_path = f.name
        try:
            clf = train_model(features, labels, model_path=model_path)
            proba = clf.predict_proba(features)
            assert proba.shape == (len(sample_findings), 2)
            # Probabilities should sum to ~1 per row
            row_sums = proba.sum(axis=1)
            np.testing.assert_allclose(row_sums, 1.0, atol=1e-6)
        finally:
            os.unlink(model_path)

    def test_invalid_model_path_raises(
        self, sample_findings: List[Dict[str, Any]]
    ) -> None:
        """Saving to an invalid path should raise OSError."""
        features = extract_features(sample_findings)
        labels = pd.Series([1, 0, 1, 1, 0, 0])
        with pytest.raises(OSError):
            train_model(features, labels, model_path="/nonexistent/dir/model.joblib")


# ---------------------------------------------------------------------------
# load_model tests
# ---------------------------------------------------------------------------


class TestLoadModel:
    """Tests for the load_model function."""

    def test_load_trained_model(self, trained_model_path: str) -> None:
        """load_model should return a valid classifier from a saved file."""
        model = load_model(trained_model_path)
        assert isinstance(model, RandomForestClassifier)

    def test_load_nonexistent_model_raises(self) -> None:
        """load_model should raise FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError, match="Model not found"):
            load_model("/nonexistent/model.joblib")

    def test_load_corrupt_model_raises(self) -> None:
        """load_model should raise an exception for corrupt model files."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False, mode="w") as f:
            f.write("this is not a valid joblib file")
            corrupt_path = f.name
        try:
            with pytest.raises(Exception):
                load_model(corrupt_path)
        finally:
            os.unlink(corrupt_path)

    def test_roundtrip_model_consistency(
        self, sample_findings: List[Dict[str, Any]]
    ) -> None:
        """A saved and loaded model should produce identical predictions."""
        features = extract_features(sample_findings)
        labels = pd.Series([1, 0, 1, 1, 0, 0])
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            model_path = f.name
        try:
            original = train_model(features, labels, model_path=model_path)
            loaded = load_model(model_path)
            orig_pred = original.predict_proba(features)
            loaded_pred = loaded.predict_proba(features)
            np.testing.assert_array_equal(orig_pred, loaded_pred)
        finally:
            os.unlink(model_path)


# ---------------------------------------------------------------------------
# predict tests
# ---------------------------------------------------------------------------


class TestPredict:
    """Tests for the predict function."""

    def test_returns_scored_findings(
        self,
        sample_findings: List[Dict[str, Any]],
        trained_model_path: str,
    ) -> None:
        """predict should return findings with vuln_score added."""
        results = predict(sample_findings, model_path=trained_model_path)
        assert len(results) == len(sample_findings)
        for r in results:
            assert "vuln_score" in r

    def test_scores_between_0_and_1(
        self,
        sample_findings: List[Dict[str, Any]],
        trained_model_path: str,
    ) -> None:
        """All vuln_scores should be between 0 and 1."""
        results = predict(sample_findings, model_path=trained_model_path)
        for r in results:
            score = r["vuln_score"]
            assert 0.0 <= score <= 1.0, f"Score {score} out of range [0, 1]"

    def test_preserves_original_fields(
        self,
        sample_findings: List[Dict[str, Any]],
        trained_model_path: str,
    ) -> None:
        """predict should preserve all original finding fields."""
        results = predict(sample_findings, model_path=trained_model_path)
        for original, scored in zip(sample_findings, results):
            for key in original:
                assert key in scored, f"Missing key '{key}' in scored finding"

    def test_predict_nonexistent_model_raises(
        self, sample_findings: List[Dict[str, Any]]
    ) -> None:
        """predict with a missing model should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            predict(sample_findings, model_path="/nonexistent/model.joblib")

    def test_predict_single_finding(self, trained_model_path: str) -> None:
        """predict should work with a single finding."""
        # Include embedding to match the features the model was trained on
        findings = [_make_finding(dangerous_calls=["eval"], embedding=[0.1, 0.2, 0.3, 0.4])]
        results = predict(findings, model_path=trained_model_path)
        assert len(results) == 1
        assert "vuln_score" in results[0]
        assert 0.0 <= results[0]["vuln_score"] <= 1.0
