"""Semantic search utilities for the read-only MCP mail server."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from ..models import MessageDetail, MessageSummary, SemanticMatch

try:  # pragma: no cover - optional dependency
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore


@dataclass
class IndexedMessage:
    summary: MessageSummary
    text: str
    embedding: "np.ndarray | None"


class SemanticIndexer:
    """In-memory semantic index with graceful fallback when embeddings are unavailable."""

    def __init__(self, *, model_name: str | None = None, batch_size: int = 16, enabled: bool = True) -> None:
        self.enabled = enabled
        self._batch_size = batch_size
        self._model_name = model_name
        self._model = None
        self._store: dict[tuple[str, str], list[IndexedMessage]] = defaultdict(list)
        if self.enabled:
            self._initialise_model()

    def _initialise_model(self) -> None:
        if not self.enabled:
            return
        try:  # pragma: no cover - optional dependency path
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name or "sentence-transformers/paraphrase-multilingual-mpnet-base-v2")
        except Exception:
            self._model = None

    def add_message(self, message: MessageDetail, *, account_id: str) -> None:
        if not self.enabled:
            return
        text = self._build_index_text(message)
        key = (account_id, message.folder_token)
        embedding = self._encode_text(text) if self._model else None
        summary = MessageSummary.model_validate(message.model_dump())
        self._store[key].append(IndexedMessage(summary=summary, text=text, embedding=embedding))

    def add_messages(self, messages: Iterable[MessageDetail], *, account_id: str) -> None:
        for message in messages:
            self.add_message(message, account_id=account_id)

    def search(self, *, account_id: str, folder_token: str | None, query: str, top_k: int = 5) -> list[SemanticMatch]:
        key_candidates = []
        if folder_token:
            key_candidates.append((account_id, folder_token))
        key_candidates.extend([(account_id, token) for token in self._existing_tokens(account_id)])  # type: ignore[arg-type]
        matches: list[SemanticMatch] = []
        query_embedding = self._encode_text(query) if self._model else None
        for key in key_candidates:
            for indexed in self._store.get(key, []):
                if self._model and query_embedding is not None and indexed.embedding is not None and np is not None:
                    score = _cosine_similarity(query_embedding, indexed.embedding)
                else:
                    score = _lexical_similarity(query, indexed.text)
                matches.append(
                    SemanticMatch(
                        message_uri=indexed.summary.resource_uri,
                        score=score,
                        summary=indexed.summary,
                        highlighted_snippet=_highlight_snippet(indexed.text, query),
                    )
                )
        matches.sort(key=lambda m: m.score, reverse=True)
        return matches[:top_k]

    def _existing_tokens(self, account_id: str) -> list[str]:
        seen = []
        for (acct, token) in self._store.keys():
            if acct == account_id:
                seen.append(token)
        return seen

    def _encode_text(self, text: str):
        if not self._model:
            return None
        if np is None:
            return None
        encoding = self._model.encode([text], batch_size=self._batch_size, convert_to_numpy=True)[0]
        norm = np.linalg.norm(encoding)
        if norm == 0:
            return encoding
        return encoding / norm

    @staticmethod
    def _build_index_text(message: MessageDetail) -> str:
        body_text = message.body.text if message.body else ""
        body_html = message.body.html if message.body else ""
        segments = [
            message.subject or "",
            " ".join(addr.address for addr in message.from_),
            " ".join(addr.address for addr in message.to),
            body_text or "",
            body_html or "",
        ]
        return "\n".join(segment for segment in segments if segment)


def _cosine_similarity(vec_a, vec_b) -> float:
    if np is None:
        return 0.0
    similarity = float(np.dot(vec_a, vec_b) / (np.linalg.norm(vec_a) * np.linalg.norm(vec_b) + 1e-9))
    return similarity


def _lexical_similarity(query: str, text: str) -> float:
    query_tokens = set(_tokenise(query))
    text_tokens = set(_tokenise(text))
    if not query_tokens or not text_tokens:
        return 0.0
    overlap = len(query_tokens & text_tokens)
    score = overlap / math.sqrt(len(query_tokens) * len(text_tokens))
    return score


def _tokenise(value: str) -> list[str]:
    return [token.lower() for token in value.split() if token.strip()]


def _highlight_snippet(text: str, query: str, window: int = 160) -> str:
    lowered = text.lower()
    index = lowered.find(query.lower())
    if index == -1:
        return text[:window]
    start = max(index - window // 2, 0)
    end = min(start + window, len(text))
    return text[start:end]
