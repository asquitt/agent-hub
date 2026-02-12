from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from src.discovery.service import DISCOVERY_SERVICE

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = Path(__file__).resolve().parent / "quality_dataset_s35.json"
DEFAULT_OUTPUT = ROOT / "data" / "discovery" / "s35_quality_results.json"


def load_dataset(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("quality dataset must be a list")
    return rows


def _dcg_fast(capability_ids: list[str], relevance: dict[str, float], k: int) -> float:
    import math

    total = 0.0
    for idx, capability_id in enumerate(capability_ids[:k], start=1):
        gain = float(relevance.get(capability_id, 0.0))
        if gain <= 0:
            continue
        total += gain / math.log2(idx + 1)
    return total


def _ndcg_at_k(capability_ids: list[str], relevance: dict[str, float], k: int) -> float:
    actual = _dcg_fast(capability_ids, relevance, k)
    ideal_ids = [cid for cid, _ in sorted(relevance.items(), key=lambda item: item[1], reverse=True)]
    ideal = _dcg_fast(ideal_ids, relevance, k)
    if ideal == 0:
        return 0.0
    return actual / ideal


def _mrr(capability_ids: list[str], relevance: dict[str, float]) -> float:
    for idx, capability_id in enumerate(capability_ids, start=1):
        if float(relevance.get(capability_id, 0.0)) > 0:
            return 1.0 / idx
    return 0.0


def run_quality_eval(
    dataset_path: Path,
    *,
    top_k: int = 5,
    repeats_per_query: int = 5,
    output_path: Path | None = None,
) -> dict[str, Any]:
    dataset = load_dataset(dataset_path)
    DISCOVERY_SERVICE.refresh_index(force=True)

    ndcg_scores: list[float] = []
    mrr_scores: list[float] = []
    latencies_ms: list[float] = []
    rows: list[dict[str, Any]] = []

    for item in dataset:
        query = str(item["query"])
        constraints = item.get("constraints", {})
        relevance = {str(cid): float(score) for cid, score in dict(item.get("relevance", {})).items()}

        sample_latencies: list[float] = []
        last_capability_ids: list[str] = []
        for _ in range(max(1, repeats_per_query)):
            started = time.perf_counter()
            response = DISCOVERY_SERVICE.semantic_discovery(query=query, constraints=constraints)
            elapsed_ms = (time.perf_counter() - started) * 1000
            sample_latencies.append(elapsed_ms)
            last_capability_ids = [str(row["capability_id"]) for row in response.get("data", [])]

        mean_latency = sum(sample_latencies) / len(sample_latencies)
        latencies_ms.extend(sample_latencies)

        ndcg = _ndcg_at_k(last_capability_ids, relevance, top_k)
        rr = _mrr(last_capability_ids, relevance)
        ndcg_scores.append(ndcg)
        mrr_scores.append(rr)
        rows.append(
            {
                "query": query,
                "constraints": constraints,
                "returned_capability_ids": last_capability_ids[:top_k],
                "ndcg_at_k": round(ndcg, 6),
                "mrr": round(rr, 6),
                "latency_ms_mean": round(mean_latency, 6),
            }
        )

    p95_latency = statistics.quantiles(latencies_ms, n=100)[94] if len(latencies_ms) >= 100 else max(latencies_ms, default=0.0)
    summary = {
        "dataset": str(dataset_path),
        "queries": len(dataset),
        "top_k": top_k,
        "repeats_per_query": repeats_per_query,
        "metrics": {
            "ndcg_at_k_mean": round(sum(ndcg_scores) / len(ndcg_scores), 6) if ndcg_scores else 0.0,
            "mrr_mean": round(sum(mrr_scores) / len(mrr_scores), 6) if mrr_scores else 0.0,
            "latency_p95_ms": round(float(p95_latency), 6),
            "latency_mean_ms": round(sum(latencies_ms) / len(latencies_ms), 6) if latencies_ms else 0.0,
        },
        "rows": rows,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run discovery quality eval for S35.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    summary = run_quality_eval(
        dataset_path=args.dataset,
        top_k=args.top_k,
        repeats_per_query=args.repeats,
        output_path=args.output,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
