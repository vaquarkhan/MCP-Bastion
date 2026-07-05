"""Benchmark tests for RBAC and FinOps context reduction (see docs/BENCHMARKS.md)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_bastion.benchmarks.finops_rbac import (
    run_all_benchmarks,
    run_discovery_filter_estimate,
    run_lexical_cache_benchmarks,
    run_output_budget_benchmarks,
    run_rbac_matrix,
)


def test_benchmark_rbac_matrix_passes():
    report = run_rbac_matrix()
    assert report["all_pass"] is True
    by_key = {(r["role"], r["tool"]): r["result"] for r in report["rows"]}
    assert by_key[("viewer", "read_file")] == "ALLOWED"
    assert by_key[("viewer", "delete_db")] == "DENIED"
    assert by_key[("admin", "delete_db")] == "ALLOWED"
    assert by_key[("nobody", "read_file")] == "DENIED"


def test_benchmark_output_budget_large_reduction():
    report = run_output_budget_benchmarks()
    rows = {r["target_input_tokens"]: r for r in report["rows"]}
    assert rows[50_000]["reduction_pct"] >= 95.0
    assert rows[10_000]["reduction_pct"] >= 90.0
    assert rows[1_500]["reduction_pct"] == 0.0
    assert rows[1_500]["applied"] is False


def test_benchmark_lexical_cache_exact_hit_paraphrase_miss():
    report = run_lexical_cache_benchmarks(similarity_threshold=0.9)
    by_case = {r["case"]: r for r in report["rows"]}
    assert by_case["exact_repeat"]["cache_hit"] is True
    assert by_case["paraphrase_extra_words"]["cache_hit"] is False
    assert by_case["paraphrase_extra_words"]["jaccard_vs_cached"] < 0.9


def test_benchmark_discovery_filter_reduces_catalog_tokens():
    report = run_discovery_filter_estimate(total_tools=20, allowlisted=3)
    assert report["reduction_pct"] >= 70.0
    assert report["tools_list_tokens_filtered"] < report["tools_list_tokens_full"]


def test_benchmark_full_report_structure():
    report = run_all_benchmarks()
    assert "rbac" in report
    assert "output_budget" in report
    assert "lexical_cache" in report
    assert "disclaimer" in report
