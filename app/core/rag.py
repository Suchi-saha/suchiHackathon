import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

import faiss
import numpy as np
import onnxruntime as ort
from rank_bm25 import BM25Okapi
from tokenizers import Tokenizer

MODEL_ROOT = Path(__file__).resolve().parents[2] / "data" / "models"
BI_ENCODER_DIR = MODEL_ROOT / "bge-large-en-v1.5"
RERANKER_DIR = MODEL_ROOT / "bge-reranker-v2-m3-ONNX"

# Stage hyperparameters (design.md section 3, Gate 3)
BM25_K1 = 1.25
BM25_B = 0.75
TOP_K = 50
HNSW_M = 32
EF_SEARCH = 64
RRF_K = 60
POOL = 40
RERANK_K = 4
RERANK_BATCH = 32
MAX_LEN = 512
# BGE retrieval queries use this instruction prefix (model card recommendation).
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


@dataclass
class Chunk:
    chunk_id: str
    tenant_id: str
    text: str

    @property
    def chunk_hash(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


def default_chunks() -> list[Chunk]:
    return [
        Chunk("pol-001", "tenant_demo", "Batch LOT-88392 safety protocol requires temperature review before release."),
        Chunk("pol-002", "tenant_demo", "A Tier 3 mutation requires asynchronous human-in-the-loop approval."),
        Chunk("pol-003", "tenant_demo", "Obfuscated PII such infomation@example[dot]com must be rejected or redacted."),
        Chunk("pol-004", "tenant_demo", "The 50K load target requires p95 below 450 ms and p99 below 590 ms."),
    ]


class _OnnxModel:
    def __init__(self, model_dir: Path, model_file: str) -> None:
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        config = json.loads((model_dir / "tokenizer_config.json").read_text(encoding="utf-8"))
        pad_token = config.get("pad_token") or "[PAD]"
        self.tokenizer.enable_truncation(max_length=MAX_LEN)
        self.tokenizer.enable_padding(pad_id=self.tokenizer.token_to_id(pad_token), pad_token=pad_token)
        self.session = ort.InferenceSession(str(model_dir / model_file), providers=["CPUExecutionProvider"])
        self._inputs = {item.name for item in self.session.get_inputs()}

    def _feed(self, encodings) -> dict[str, np.ndarray]:
        feed = {
            "input_ids": np.array([e.ids for e in encodings], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in encodings], dtype=np.int64),
        }
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.array([e.type_ids for e in encodings], dtype=np.int64)
        return feed


class BiEncoder(_OnnxModel):
    def __init__(self) -> None:
        super().__init__(BI_ENCODER_DIR, "onnx/model.onnx")

    def encode(self, texts: list[str]) -> np.ndarray:
        output = self.session.run(None, self._feed(self.tokenizer.encode_batch(texts)))[0]
        vectors = output[:, 0, :].astype(np.float32)  # CLS pooling
        return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)


class CrossEncoder(_OnnxModel):
    def __init__(self) -> None:
        super().__init__(RERANKER_DIR, "onnx/model_fp16.onnx")

    def score(self, query: str, passages: list[str]) -> list[float]:
        scores: list[float] = []
        for start in range(0, len(passages), RERANK_BATCH):
            batch = passages[start:start + RERANK_BATCH]
            encodings = self.tokenizer.encode_batch([(query, passage) for passage in batch])
            logits = self.session.run(None, self._feed(encodings))[0].reshape(-1).astype(np.float32)
            scores.extend(float(value) for value in 1.0 / (1.0 + np.exp(-logits)))  # sigmoid
        return scores


class HybridRAG:
    """Three-stage tenant-scoped retrieval: BM25 + bi-encoder/HNSW -> RRF -> cross-encoder rerank."""

    def __init__(self, chunks: list[Chunk] | None = None) -> None:
        self.chunks = list(chunks) if chunks is not None else default_chunks()
        self._encoder: BiEncoder | None = None
        self._reranker: CrossEncoder | None = None
        self._embeddings: dict[str, np.ndarray] = {}
        self.last_timings_ms: dict[str, float] = {}

    @property
    def encoder(self) -> BiEncoder:
        if self._encoder is None:
            self._encoder = BiEncoder()
        return self._encoder

    @property
    def reranker(self) -> CrossEncoder:
        if self._reranker is None:
            self._reranker = CrossEncoder()
        return self._reranker

    @staticmethod
    def tokenize(text: str) -> list[str]:
        return re.findall(r"[A-Za-z0-9_-]+", text.lower())

    def _ensure_embeddings(self, chunks: list[Chunk]) -> None:
        missing = [chunk for chunk in chunks if chunk.chunk_id not in self._embeddings]
        if missing:
            vectors = self.encoder.encode([chunk.text for chunk in missing])
            for chunk, vector in zip(missing, vectors):
                self._embeddings[chunk.chunk_id] = vector

    def retrieve(self, tenant_id: str, query: str, limit: int = RERANK_K) -> list[tuple[Chunk, float]]:
        scoped = [chunk for chunk in self.chunks if chunk.tenant_id == tenant_id]
        if not scoped:
            return []
        timings: dict[str, float] = {}

        # Stage 1: sparse lexical (BM25)
        started = time.perf_counter()
        bm25 = BM25Okapi([self.tokenize(chunk.text) for chunk in scoped], k1=BM25_K1, b=BM25_B)
        bm25_scores = bm25.get_scores(self.tokenize(query))
        bm25_rank = sorted(range(len(scoped)), key=lambda i: bm25_scores[i], reverse=True)[:TOP_K]
        timings["bm25_ms"] = round((time.perf_counter() - started) * 1000, 2)

        # Stage 2: dense semantic (bge-large + FAISS HNSW, inner product on normalized vectors = cosine)
        started = time.perf_counter()
        self._ensure_embeddings(scoped)
        matrix = np.stack([self._embeddings[chunk.chunk_id] for chunk in scoped])
        index = faiss.IndexHNSWFlat(matrix.shape[1], HNSW_M, faiss.METRIC_INNER_PRODUCT)
        index.hnsw.efSearch = EF_SEARCH
        index.add(matrix)
        query_vector = self.encoder.encode([QUERY_INSTRUCTION + query])
        _, neighbours = index.search(query_vector, min(TOP_K, len(scoped)))
        dense_rank = [int(i) for i in neighbours[0] if i >= 0]
        timings["dense_ms"] = round((time.perf_counter() - started) * 1000, 2)

        # Rank fusion: Reciprocal Rank Fusion, k=60, pool=40, dedup by chunk_hash
        started = time.perf_counter()
        fused: dict[int, float] = {}
        for ranking in (bm25_rank, dense_rank):
            for rank, index_pos in enumerate(ranking, start=1):
                fused[index_pos] = fused.get(index_pos, 0.0) + 1.0 / (RRF_K + rank)
        ordered = sorted(fused, key=lambda i: fused[i], reverse=True)
        seen: set[str] = set()
        pool: list[int] = []
        for position in ordered:
            digest = scoped[position].chunk_hash
            if digest in seen:
                continue
            seen.add(digest)
            pool.append(position)
            if len(pool) == POOL:
                break
        timings["rrf_ms"] = round((time.perf_counter() - started) * 1000, 2)

        # Stage 3: cross-encoder rerank (sigmoid scores)
        started = time.perf_counter()
        scores = self.reranker.score(query, [scoped[i].text for i in pool])
        ranked = sorted(zip(pool, scores), key=lambda item: item[1], reverse=True)[:min(limit, RERANK_K)]
        timings["rerank_ms"] = round((time.perf_counter() - started) * 1000, 2)

        self.last_timings_ms = timings
        return [(scoped[position], float(score)) for position, score in ranked]
