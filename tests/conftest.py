"""
Test configuration for vulnpredict.

Stubs out optional heavy dependencies (transformers, torch) so that
py_analyzer can be imported without requiring GPU libraries.
"""

import sys
import types
from unittest import mock

import numpy as np

# ---------------------------------------------------------------------------
# Create fake transformers module
# ---------------------------------------------------------------------------
_fake_transformers = types.ModuleType("transformers")


def _fake_from_pretrained(name):
    """Return a mock tokenizer or model."""
    return mock.MagicMock()


_fake_transformers.AutoTokenizer = mock.MagicMock()
_fake_transformers.AutoTokenizer.from_pretrained = _fake_from_pretrained
_fake_transformers.AutoModel = mock.MagicMock()
_fake_transformers.AutoModel.from_pretrained = _fake_from_pretrained

# ---------------------------------------------------------------------------
# Create fake torch module
# ---------------------------------------------------------------------------
_fake_torch = types.ModuleType("torch")
_fake_torch.no_grad = mock.MagicMock(
    return_value=mock.MagicMock(
        __enter__=mock.MagicMock(return_value=None),
        __exit__=mock.MagicMock(return_value=False),
    )
)

# ---------------------------------------------------------------------------
# Inject into sys.modules BEFORE any test imports py_analyzer
# ---------------------------------------------------------------------------
if "transformers" not in sys.modules:
    sys.modules["transformers"] = _fake_transformers
if "torch" not in sys.modules:
    sys.modules["torch"] = _fake_torch

# ---------------------------------------------------------------------------
# Now patch get_code_embedding globally so no test accidentally calls CodeBERT
# ---------------------------------------------------------------------------
import vulnpredict.py_analyzer as _pa  # noqa: E402

_original_get_code_embedding = _pa.get_code_embedding


def _fake_embedding(code):
    """Return a deterministic dummy 768-dim embedding."""
    return [0.0] * 768


_pa.get_code_embedding = _fake_embedding
