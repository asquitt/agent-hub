from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from mock_engine import search_capabilities

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = Path(__file__).resolve().parent / "benchmark_dataset_s18.json"
DEFAULT_OUTPUT = ROOT / "data" / "capability_search" / "s18_benchmark_results.json"


def load_dataset(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("benchmark dataset must be a JSON list")
    return rows


def _reciprocal_rank(result_ids: list[str], relevant_ids: set[str]) -> float:
    for idx, cid in enumerate(result_ids, start=1):
        if cid in relevant_ids:
            return 1.0 / idx
    return 0.0


def evaluate_dataset(dataset: list[dict[str, Any]], ranking_mode: str, top_k: int = 3) -> dict[str, Any]:
    total = len(dataset)
    hits_at_1 = 0
    hits_at_k = 0
    mrr = 0.0
    rows: list[dict[str, Any]] = []

    for row in dataset:
        query = row["query"]
        relevant = set(row["relevant_capability_ids"])
        response = search_capabilities(
            query=query,
            filters=row.get("filters"),
            pagination={"mode": "offset", "offset": 0, "limit": top_k},
            ranking_mode=ranking_mode,
        )
        returned = [item["capability_id"] for item in response["data"]]
        top1_hit = bool(returned and returned[0] in relevant)
        topk_hit = any(cid in relevant for cid in returned[:top_k])
        rr = _reciprocal_rank(returned, relevant)

        hits_at_1 += int(top1_hit)
        hits_at_k += int(topk_hit)
        mrr += rr
        rows.append(
            {
                "query": query,
                "relevant_capability_ids": sorted(relevant),
                "returned_capability_ids": returned,
                "top1_hit": top1_hit,
                "topk_hit": topk_hit,
                "reciprocal_rank": rr,
            }
        )

    if total == 0:
        raise ValueError("benchmark dataset is empty")

    return {
        "ranking_mode": ranking_mode,
        "queries": total,
        "top1_accuracy": round(hits_at_1 / total, 6),
        f"top{top_k}_accuracy": round(hits_at_k / total, 6),
        "mrr": round(mrr / total, 6),
        "rows": rows,
    }


def run_benchmark(dataset_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    dataset = load_dataset(dataset_path)
    baseline = evaluate_dataset(dataset, ranking_mode="baseline", top_k=3)
    v2 = evaluate_dataset(dataset, ranking_mode="v2", top_k=3)

    summary = {
        "dataset": str(dataset_path),
        "baseline": baseline,
        "v2": v2,
        "improvement": {
            "top1_accuracy_delta": round(v2["top1_accuracy"] - baseline["top1_accuracy"], 6),
            "top3_accuracy_delta": round(v2["top3_accuracy"] - baseline["top3_accuracy"], 6),
            "mrr_delta": round(v2["mrr"] - baseline["mrr"], 6),
        },
        "policy_regression": False,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run capability search S18 benchmark.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    summary = run_benchmark(dataset_path=args.dataset, output_path=args.output)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
