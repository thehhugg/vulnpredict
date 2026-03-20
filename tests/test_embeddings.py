"""Tests for the CodeBERT embeddings module."""

from __future__ import annotations

import ast
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from vulnpredict.embeddings import (
    EMBEDDING_DIM,
    _extract_python_function,
    combine_features,
    enrich_findings_with_embeddings,
    extract_code_context,
    generate_embedding,
    generate_embeddings_batch,
    is_model_available,
)


# ---------------------------------------------------------------------------
# is_model_available
# ---------------------------------------------------------------------------

class TestIsModelAvailable:
    def test_returns_bool(self):
        result = is_model_available()
        assert isinstance(result, bool)

    @patch("vulnpredict.embeddings._model_available", None)
    def test_caches_result(self):
        """After first call, subsequent calls return cached value."""
        result1 = is_model_available()
        result2 = is_model_available()
        assert result1 == result2


# ---------------------------------------------------------------------------
# generate_embedding – graceful degradation
# ---------------------------------------------------------------------------

class TestGenerateEmbeddingFallback:
    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_returns_zero_vector_when_unavailable(self, mock_avail):
        emb = generate_embedding("print('hello')")
        assert isinstance(emb, np.ndarray)
        assert emb.shape == (EMBEDDING_DIM,)
        assert np.all(emb == 0)
        assert emb.dtype == np.float32

    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_zero_vector_for_empty_string(self, mock_avail):
        emb = generate_embedding("")
        assert emb.shape == (EMBEDDING_DIM,)
        assert np.all(emb == 0)


# ---------------------------------------------------------------------------
# generate_embedding – with mocked model
# ---------------------------------------------------------------------------

class TestGenerateEmbeddingWithModel:
    def _mock_model_and_tokenizer(self):
        """Create mock tokenizer and model that return realistic shapes."""
        mock_tokenizer = MagicMock()
        mock_tokenizer.return_value = {
            "input_ids": MagicMock(),
            "attention_mask": MagicMock(),
        }

        mock_output = MagicMock()
        # Create a mock tensor that behaves like torch output
        fake_hidden = MagicMock()
        cls_token = MagicMock()
        squeezed = MagicMock()
        squeezed.cpu.return_value = squeezed
        squeezed.numpy.return_value = np.random.randn(EMBEDDING_DIM).astype(np.float32)
        cls_token.squeeze.return_value = squeezed
        fake_hidden.__getitem__ = MagicMock(return_value=cls_token)
        mock_output.last_hidden_state = fake_hidden

        mock_model = MagicMock()
        mock_model.return_value = mock_output
        return mock_tokenizer, mock_model

    @patch("vulnpredict.embeddings._load_model")
    @patch("vulnpredict.embeddings.is_model_available", return_value=True)
    def test_returns_embedding_with_model(self, mock_avail, mock_load):
        mock_tokenizer, mock_model = self._mock_model_and_tokenizer()
        mock_load.return_value = (mock_tokenizer, mock_model)

        # We need to mock torch at the import level inside generate_embedding
        mock_torch = MagicMock()
        mock_torch.cuda.is_available.return_value = False
        mock_torch.no_grad.return_value.__enter__ = MagicMock()
        mock_torch.no_grad.return_value.__exit__ = MagicMock(return_value=False)

        with patch.dict("sys.modules", {"torch": mock_torch}):
            emb = generate_embedding("def foo(): pass")

        assert isinstance(emb, np.ndarray)
        assert emb.shape == (EMBEDDING_DIM,)


# ---------------------------------------------------------------------------
# generate_embeddings_batch – graceful degradation
# ---------------------------------------------------------------------------

class TestGenerateEmbeddingsBatchFallback:
    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_returns_zero_matrix_when_unavailable(self, mock_avail):
        snippets = ["print('a')", "print('b')", "print('c')"]
        result = generate_embeddings_batch(snippets)
        assert isinstance(result, np.ndarray)
        assert result.shape == (3, EMBEDDING_DIM)
        assert np.all(result == 0)

    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_empty_input(self, mock_avail):
        result = generate_embeddings_batch([])
        assert result.shape == (0, EMBEDDING_DIM)


# ---------------------------------------------------------------------------
# extract_code_context
# ---------------------------------------------------------------------------

class TestExtractCodeContext:
    def test_extracts_window(self, tmp_path):
        code = "\n".join(f"line_{i}" for i in range(1, 31))
        f = tmp_path / "test.js"
        f.write_text(code)

        snippet = extract_code_context(str(f), 15, context_lines=3)
        assert "line_12" in snippet
        assert "line_18" in snippet

    def test_extracts_python_function(self, tmp_path):
        code = """import os

def safe_func():
    return 1

def vulnerable_func():
    x = eval(input())
    return x

def another_func():
    return 2
"""
        f = tmp_path / "test.py"
        f.write_text(code)

        snippet = extract_code_context(str(f), 7)
        assert "vulnerable_func" in snippet
        assert "eval" in snippet

    def test_nonexistent_file(self):
        snippet = extract_code_context("/nonexistent/file.py", 1)
        assert snippet == ""

    def test_non_python_file_uses_window(self, tmp_path):
        code = "\n".join(f"const x{i} = {i};" for i in range(1, 21))
        f = tmp_path / "test.js"
        f.write_text(code)

        snippet = extract_code_context(str(f), 10, context_lines=2)
        assert "x8" in snippet or "x9" in snippet
        assert "x12" in snippet or "x11" in snippet


# ---------------------------------------------------------------------------
# _extract_python_function
# ---------------------------------------------------------------------------

class TestExtractPythonFunction:
    def test_extracts_function(self):
        source = """def foo():
    x = 1
    return x

def bar():
    y = 2
    return y
"""
        result = _extract_python_function(source, 2)
        assert result is not None
        assert "foo" in result
        assert "x = 1" in result

    def test_returns_none_for_module_level(self):
        source = """x = 1
y = 2
"""
        result = _extract_python_function(source, 1)
        assert result is None

    def test_returns_none_for_syntax_error(self):
        result = _extract_python_function("def foo(:", 1)
        assert result is None

    def test_async_function(self):
        source = """async def handler():
    await do_something()
    return result
"""
        result = _extract_python_function(source, 2)
        assert result is not None
        assert "handler" in result


# ---------------------------------------------------------------------------
# enrich_findings_with_embeddings
# ---------------------------------------------------------------------------

class TestEnrichFindings:
    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_adds_embedding_key(self, mock_avail, tmp_path):
        code = "x = eval(input())\n"
        f = tmp_path / "test.py"
        f.write_text(code)

        findings = [
            {"file": str(f), "line": 1, "type": "code_injection"},
        ]
        result = enrich_findings_with_embeddings(findings)
        assert len(result) == 1
        assert "embedding" in result[0]
        assert result[0]["embedding"].shape == (EMBEDDING_DIM,)

    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_empty_findings(self, mock_avail):
        result = enrich_findings_with_embeddings([])
        assert result == []

    @patch("vulnpredict.embeddings.is_model_available", return_value=False)
    def test_missing_file_key(self, mock_avail):
        findings = [{"line": 1, "type": "test"}]
        result = enrich_findings_with_embeddings(findings)
        assert "embedding" in result[0]


# ---------------------------------------------------------------------------
# combine_features
# ---------------------------------------------------------------------------

class TestCombineFeatures:
    def test_concatenation(self):
        static = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        embedding = np.zeros(EMBEDDING_DIM, dtype=np.float32)
        combined = combine_features(static, embedding)
        assert combined.shape == (3 + EMBEDDING_DIM,)
        assert combined[0] == 1.0
        assert combined[1] == 2.0
        assert combined[2] == 3.0

    def test_preserves_values(self):
        static = np.array([10.0], dtype=np.float32)
        embedding = np.ones(EMBEDDING_DIM, dtype=np.float32) * 0.5
        combined = combine_features(static, embedding)
        assert combined[0] == 10.0
        assert combined[-1] == 0.5
