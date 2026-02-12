from __future__ import annotations

import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

from src.discovery.service import DISCOVERY_SERVICE


random.seed(42)


def _run_contract() -> float:
    t = time.perf_counter()
    DISCOVERY_SERVICE.contract_match(
        input_required=["invoice_text"],
        output_required=["vendor", "total"],
        max_cost_usd=0.03,
    )
    return (time.perf_counter() - t) * 1000


def _run_compat() -> float:
    t = time.perf_counter()
    DISCOVERY_SERVICE.compatibility_report(
        my_schema={"type": "object", "required": ["ticket_text", "account_id", "action"]},
        agent_id="support-orchestrator",
    )
    return (time.perf_counter() - t) * 1000


def _run_semantic() -> float:
    t = time.perf_counter()
    DISCOVERY_SERVICE.semantic_discovery(
        query="resolve support ticket",
        constraints={"min_trust_score": 0.8, "max_cost_usd": 0.2},
    )
    return (time.perf_counter() - t) * 1000


def test_load_1000_mixed_queries_meet_slas() -> None:
    tasks = []
    for _ in range(1000):
        pick = random.random()
        if pick < 0.4:
            tasks.append(("contract", _run_contract))
        elif pick < 0.7:
            tasks.append(("compat", _run_compat))
        else:
            tasks.append(("semantic", _run_semantic))

    results = {"contract": [], "compat": [], "semantic": []}

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [(label, pool.submit(fn)) for label, fn in tasks]
        for label, future in futures:
            results[label].append(future.result())

    contract_p95 = statistics.quantiles(results["contract"], n=100)[94]
    compat_p95 = statistics.quantiles(results["compat"], n=100)[94]
    semantic_p95 = statistics.quantiles(results["semantic"], n=100)[94]

    assert contract_p95 < 100, f"contract p95={contract_p95:.3f}ms"
    assert compat_p95 < 100, f"compat p95={compat_p95:.3f}ms"
    assert semantic_p95 < 300, f"semantic p95={semantic_p95:.3f}ms"
