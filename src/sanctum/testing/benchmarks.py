import time
import sqlite3
import json
import statistics
from typing import Dict, Any, List, Optional
from pydantic import BaseModel


class BenchmarkMetric(BaseModel):
    benchmark_id: str
    operation_name: str
    target_media: str
    duration_seconds: float
    throughput_mbps: float
    cpu_percent: float = 0.0
    passed: bool
    threshold_mbps: float
    notes: Optional[str] = None
    timestamp: float


class PerformanceBenchmarkRunner:
    """
    Performance Benchmark Runner & Result Database.
    Evaluates:
    - Overwrite throughput (MB/s) vs NIST/DoD regression thresholds
    - Aho-Corasick file carving streaming throughput (MB/s)
    - Hash calculation throughput (SHA-256 MB/s)
    - Relational SQLite storage of historical benchmarks
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmarks (
                    benchmark_id TEXT PRIMARY KEY,
                    operation_name TEXT NOT NULL,
                    target_media TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    throughput_mbps REAL NOT NULL,
                    cpu_percent REAL NOT NULL,
                    passed INTEGER NOT NULL,
                    threshold_mbps REAL NOT NULL,
                    notes TEXT,
                    timestamp REAL NOT NULL
                )
                """
            )

    def run_hash_benchmark(self, data_size_bytes: int = 50 * 1024 * 1024, threshold_mbps: float = 100.0) -> BenchmarkMetric:
        import hashlib
        data = b"\xaa" * (1024 * 1024)  # 1MB buffer
        iters = data_size_bytes // len(data)

        hasher = hashlib.sha256()
        start = time.perf_counter()
        for _ in range(iters):
            hasher.update(data)
        hasher.hexdigest()
        duration = max(0.001, time.perf_counter() - start)

        throughput = (data_size_bytes / (1024 * 1024)) / duration
        passed = throughput >= threshold_mbps

        metric = BenchmarkMetric(
            benchmark_id=f"BM-HASH-{int(time.time() * 1000)}",
            operation_name="SHA256_STREAMING_HASH",
            target_media="MEMORY_BUFFER",
            duration_seconds=round(duration, 4),
            throughput_mbps=round(throughput, 2),
            passed=passed,
            threshold_mbps=threshold_mbps,
            notes=f"Processed {data_size_bytes / (1024 * 1024):.1f} MB",
            timestamp=time.time(),
        )
        self.record_metric(metric)
        return metric

    def run_carving_benchmark(self, data_size_bytes: int = 10 * 1024 * 1024, threshold_mbps: float = 20.0) -> BenchmarkMetric:
        from sanctum.carving.matcher import AhoCorasickMatcher
        # 1. Initialize and compile Aho-Corasick matcher before timing
        matcher = AhoCorasickMatcher()
        matcher.add_pattern(b"\xff\xd8\xff", "JPEG")
        matcher.add_pattern(b"\x89PNG\r\n\x1a\n", "PNG")
        matcher.add_pattern(b"%PDF-", "PDF")
        matcher.compile()

        # 2. Generate exactly data_size_bytes of synthetic input using repetition and slicing
        pattern_unit = b"PADDING_SECTORS_DATA" * 50 + b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\xff\xd9"
        repeat_count = (data_size_bytes // len(pattern_unit)) + 1
        data = (pattern_unit * repeat_count)[:data_size_bytes]
        assert len(data) == data_size_bytes

        # 3. Perform a small warm-up scan outside the measured section
        warmup_len = min(len(data), 64 * 1024)
        _ = matcher.search(data[:warmup_len])

        # 4. Perform at least three full scans
        durations: List[float] = []
        for _ in range(3):
            start = time.perf_counter()
            _ = matcher.search(data)
            elapsed = max(0.0001, time.perf_counter() - start)
            durations.append(elapsed)

        # 5. Use the median scan duration to calculate throughput
        median_duration = max(0.0001, statistics.median(durations))
        throughput = (len(data) / (1024 * 1024)) / median_duration
        passed = throughput >= threshold_mbps

        metric = BenchmarkMetric(
            benchmark_id=f"BM-CARVE-{int(time.time() * 1000)}",
            operation_name="AHO_CORASICK_SIGNATURE_SCAN",
            target_media="STREAMING_CLUSTERS",
            duration_seconds=round(median_duration, 4),
            throughput_mbps=round(throughput, 2),
            passed=passed,
            threshold_mbps=threshold_mbps,
            notes=f"Scanned exactly {len(data)} bytes ({len(data) / (1024 * 1024):.2f} MB, 3-run median)",
            timestamp=time.time(),
        )
        self.record_metric(metric)
        return metric

    def record_metric(self, metric: BenchmarkMetric) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO benchmarks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metric.benchmark_id,
                    metric.operation_name,
                    metric.target_media,
                    metric.duration_seconds,
                    metric.throughput_mbps,
                    metric.cpu_percent,
                    1 if metric.passed else 0,
                    metric.threshold_mbps,
                    metric.notes,
                    metric.timestamp,
                ),
            )

    def list_metrics(self) -> List[BenchmarkMetric]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM benchmarks ORDER BY timestamp DESC")
        return [
            BenchmarkMetric(
                benchmark_id=r["benchmark_id"],
                operation_name=r["operation_name"],
                target_media=r["target_media"],
                duration_seconds=r["duration_seconds"],
                throughput_mbps=r["throughput_mbps"],
                cpu_percent=r["cpu_percent"],
                passed=bool(r["passed"]),
                threshold_mbps=r["threshold_mbps"],
                notes=r["notes"],
                timestamp=r["timestamp"],
            )
            for r in cur.fetchall()
        ]
