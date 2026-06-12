"""Benchmark suite compatibility exports."""

from __future__ import annotations

from benchmark_loader import (
    BenchmarkValidationError,
    benchmark_counts,
    evaluation_matrix_size,
    list_available_benchmarks,
    load_benchmark,
    load_standard_benchmark,
    validate_benchmark,
)


__all__ = [
    "BenchmarkValidationError",
    "benchmark_counts",
    "evaluation_matrix_size",
    "list_available_benchmarks",
    "load_benchmark",
    "load_standard_benchmark",
    "validate_benchmark",
]
