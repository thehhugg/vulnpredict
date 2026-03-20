"""CodeBERT-based code embeddings for semantic vulnerability understanding.

This module provides functions to generate code embeddings using the
microsoft/codebert-base model from Hugging Face. When transformers/torch
are not installed, it falls back gracefully to zero-vector embeddings.
"""

from __future__ import annotations

import ast
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Embedding dimension for CodeBERT (768-dim hidden state)
EMBEDDING_DIM: int = 768

# Lazy-loaded model and tokenizer singletons
_model: Any = None
_tokenizer: Any = None
_model_available: Optional[bool] = None


def is_model_available() -> bool:
    """Check whether transformers and torch are installed."""
    global _model_available
    if _model_available is not None:
        return _model_available
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        _model_available = True
    except ImportError:
        _model_available = False
    return _model_available


def _load_model() -> Tuple[Any, Any]:
    """Load the CodeBERT model and tokenizer (lazy singleton)."""
    global _model, _tokenizer
    if _model is not None and _tokenizer is not None:
        return _tokenizer, _model

    if not is_model_available():
        raise RuntimeError(
            "transformers and torch are required for CodeBERT embeddings. "
            "Install with: pip install vulnpredict[ml]"
        )

    import torch
    from transformers import AutoModel, AutoTokenizer

    model_name = "microsoft/codebert-base"
    logger.info("Loading CodeBERT model: %s", model_name)
    _tokenizer = AutoTokenizer.from_pretrained(model_name)
    _model = AutoModel.from_pretrained(model_name)
    _model.eval()

    # Move to GPU if available
    if torch.cuda.is_available():
        _model = _model.cuda()
        logger.info("CodeBERT model loaded on GPU")
    else:
        logger.info("CodeBERT model loaded on CPU")

    return _tokenizer, _model


def generate_embedding(code_snippet: str, max_length: int = 512) -> np.ndarray:
    """Generate a CodeBERT embedding for a code snippet.

    Args:
        code_snippet: Source code text to embed.
        max_length: Maximum token length (CodeBERT supports up to 512).

    Returns:
        A 1-D numpy array of shape (768,) representing the code embedding.
        Returns a zero vector if the model is not available.
    """
    if not is_model_available():
        logger.debug("CodeBERT not available; returning zero embedding")
        return np.zeros(EMBEDDING_DIM, dtype=np.float32)

    import torch

    tokenizer, model = _load_model()

    inputs = tokenizer(
        code_snippet,
        return_tensors="pt",
        max_length=max_length,
        truncation=True,
        padding=True,
    )

    if torch.cuda.is_available():
        inputs = {k: v.cuda() for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)

    # Use the [CLS] token embedding as the code representation
    cls_embedding = outputs.last_hidden_state[:, 0, :].squeeze(0)
    return cls_embedding.cpu().numpy().astype(np.float32)


def generate_embeddings_batch(
    code_snippets: Sequence[str], max_length: int = 512, batch_size: int = 16
) -> np.ndarray:
    """Generate CodeBERT embeddings for a batch of code snippets.

    Args:
        code_snippets: List of source code texts to embed.
        max_length: Maximum token length per snippet.
        batch_size: Number of snippets to process at once.

    Returns:
        A 2-D numpy array of shape (n, 768).
    """
    if not code_snippets:
        return np.zeros((0, EMBEDDING_DIM), dtype=np.float32)

    if not is_model_available():
        logger.debug("CodeBERT not available; returning zero embeddings")
        return np.zeros((len(code_snippets), EMBEDDING_DIM), dtype=np.float32)

    import torch

    tokenizer, model = _load_model()
    all_embeddings: List[np.ndarray] = []

    for i in range(0, len(code_snippets), batch_size):
        batch = list(code_snippets[i : i + batch_size])
        inputs = tokenizer(
            batch,
            return_tensors="pt",
            max_length=max_length,
            truncation=True,
            padding=True,
        )

        if torch.cuda.is_available():
            inputs = {k: v.cuda() for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)

        cls_embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
        all_embeddings.append(cls_embeddings.astype(np.float32))

    return np.vstack(all_embeddings)


def extract_code_context(
    filepath: str, line_number: int, context_lines: int = 10
) -> str:
    """Extract a code snippet around a finding location.

    Attempts to extract the enclosing function body. If that fails,
    falls back to extracting a window of lines around the target line.

    Args:
        filepath: Path to the source file.
        line_number: The line number of the finding (1-indexed).
        context_lines: Number of lines to include above and below if
            function extraction fails.

    Returns:
        The extracted code snippet as a string.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
            lines = source.splitlines()
    except (OSError, IOError):
        return ""

    # Try to find the enclosing function for Python files
    if filepath.endswith(".py"):
        snippet = _extract_python_function(source, line_number)
        if snippet:
            return snippet

    # Fallback: extract a window of lines
    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number + context_lines)
    return "\n".join(lines[start:end])


def _extract_python_function(source: str, line_number: int) -> Optional[str]:
    """Extract the enclosing Python function body for a given line."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None)
            if end is None:
                continue
            if start <= line_number <= end:
                lines = source.splitlines()
                return "\n".join(lines[start - 1 : end])

    return None


def enrich_findings_with_embeddings(
    findings: List[Dict[str, Any]],
    batch_size: int = 16,
) -> List[Dict[str, Any]]:
    """Add CodeBERT embedding vectors to a list of findings.

    Each finding dict gets an 'embedding' key containing a numpy array
    of shape (768,). If the model is not available, zero vectors are used.

    Args:
        findings: List of finding dicts with 'file' and 'line' keys.
        batch_size: Batch size for embedding generation.

    Returns:
        The same list of findings, each enriched with an 'embedding' key.
    """
    if not findings:
        return findings

    # Extract code context for each finding
    snippets: List[str] = []
    for finding in findings:
        filepath = finding.get("file", "")
        line = finding.get("line", 1)
        snippet = extract_code_context(filepath, line)
        snippets.append(snippet if snippet else "")

    # Generate embeddings in batch
    embeddings = generate_embeddings_batch(snippets, batch_size=batch_size)

    # Attach embeddings to findings
    for finding, embedding in zip(findings, embeddings):
        finding["embedding"] = embedding

    return findings


def combine_features(
    static_features: np.ndarray, embedding: np.ndarray
) -> np.ndarray:
    """Concatenate static features with a CodeBERT embedding.

    Args:
        static_features: 1-D array of numeric features from the existing pipeline.
        embedding: 1-D array of shape (768,) from CodeBERT.

    Returns:
        A 1-D concatenated feature vector.
    """
    return np.concatenate([static_features, embedding])
