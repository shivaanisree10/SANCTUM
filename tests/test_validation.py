import os
import pytest
import hashlib
from pathlib import Path

from sanctum.testing.corpus import KnownAnswerCorpus
from sanctum.testing.fault_injector import ChaosVirtualDevice, ChaosFaultInjector
from sanctum.testing.benchmarks import PerformanceBenchmarkRunner
from sanctum.testing.dossier import ValidationDossierGenerator
from sanctum.dal import DeviceReadError, DeviceWriteError
from sanctum.carving.matcher import AhoCorasickMatcher
from sanctum.fs.fat import FATParser
from sanctum.safety.guard import SafetyGuard, SafetyError
from sanctum.safety.models import OperationMode
from sanctum.dal.models import DeviceInfo


def test_known_answer_corpus_and_scoring():
    corpus = KnownAnswerCorpus.get_ground_truth_catalog()
    assert len(corpus) >= 4

    jpeg_item = corpus["CORPUS-JPEG-001"]
    assert jpeg_item.extension == "jpg"
    assert hashlib.sha256(jpeg_item.data_bytes).hexdigest() == jpeg_item.expected_sha256

    pdf_item = corpus["CORPUS-PDF-001"]
    assert pdf_item.extension == "pdf"
    assert hashlib.sha256(pdf_item.data_bytes).hexdigest() == pdf_item.expected_sha256

    # Test Automatic Recovery Scoring
    recovered_items = [jpeg_item, pdf_item]
    ground_truth = list(corpus.values())

    true_positives = sum(1 for r in recovered_items if any(g.expected_sha256 == r.expected_sha256 for g in ground_truth))
    precision = true_positives / len(recovered_items)
    recall = true_positives / len(ground_truth)
    assert precision == 1.0
    assert recall >= 0.5


def test_controlled_fault_injection():
    dev = ChaosVirtualDevice(serial="FAULT-TEST-001", size_bytes=1048576, sector_size=512)

    # 1. Normal read/write
    dev.write_sector(10, b"\xaa" * 512)
    assert dev.read_sector(10) == b"\xaa" * 512

    # 2. Inject bad read sector at LBA 25
    dev.fault_injector.inject_bad_read_sectors(range(25, 26))
    with pytest.raises(DeviceReadError):
        dev.read_sector(25)

    # 3. Inject bad write sector at LBA 30
    dev.fault_injector.inject_bad_write_sectors(range(30, 31))
    with pytest.raises(DeviceWriteError):
        dev.write_sector(30, b"\xbb" * 512)

    # 4. Inject sector data corruption at LBA 40
    corrupted_data = b"\xde\xad\xbe\xef" * 128
    dev.fault_injector.inject_sector_corruption(40, corrupted_data)
    assert dev.read_sector(40) == corrupted_data


def test_complete_safety_matrix():
    guard = SafetyGuard()

    # Safety Test 1: System Boot Drive Protection
    boot_dev = DeviceInfo(
        path="\\\\.\\PhysicalDrive0",
        serial="SYS-BOOT-DISK",
        capacity_bytes=512 * 1024 * 1024,
        sector_size=512,
        lba_count=1024 * 1024,
        is_virtual=False,
    )
    with pytest.raises(SafetyError):
        guard.request_token(boot_dev, "J1", "O1", OperationMode.SANITIZATION, confirmed=True)

    # Safety Test 2: Unconfirmed operation refusal
    virt_dev = DeviceInfo(
        path="virtual://disposable",
        serial="DISPOSABLE-01",
        capacity_bytes=104857600,
        sector_size=512,
        lba_count=204800,
        is_virtual=True,
    )
    with pytest.raises(SafetyError):
        guard.request_token(virt_dev, "J2", "O2", OperationMode.SANITIZATION, confirmed=False)

    # Safety Test 3: Ambiguous serial refusal
    empty_serial_dev = DeviceInfo(
        path="virtual://disposable",
        serial="",
        capacity_bytes=104857600,
        sector_size=512,
        lba_count=204800,
        is_virtual=True,
    )
    with pytest.raises(SafetyError):
        guard.request_token(empty_serial_dev, "J3", "O3", OperationMode.SANITIZATION, confirmed=True)


def test_parser_fuzzing_resilience():
    # Test parser isolation and cycle/recursion bounding against fuzzed / malformed inputs
    dev_noise = ChaosVirtualDevice(serial="FUZZ-NOISE-01", size_bytes=1048576)
    dev_noise.write_sector(0, os.urandom(512))
    res_noise = FATParser.probe(dev_noise)
    assert res_noise == 0.0  # Rejected safely, zero crash

    # Fuzz input 2: truncated / invalid boot sector (512 bytes)
    dev_trunc = ChaosVirtualDevice(serial="FUZZ-TRUNC-01", size_bytes=1048576)
    dev_trunc.write_sector(0, (b"\xeb\x3c\x90MSDOS5.0" + b"\x00" * 502)[:512])
    res_trunc = FATParser.probe(dev_trunc)
    assert res_trunc == 0.0

    # Fuzz input 3: Carving scanner robustness against cyclic patterns
    from sanctum.carving.matcher import AhoCorasickMatcher
    matcher = AhoCorasickMatcher()
    matcher.add_pattern(b"\xff\xd8\xff", "JPEG")
    matcher.compile()
    cyclic_noise = (b"\xff\xd8\xff\xe0" + b"\x00" * 20) * 100
    carved = matcher.search(cyclic_noise)
    assert isinstance(carved, list)


def test_performance_benchmarks_and_thresholds(tmp_path):
    db_file = str(tmp_path / "benchmarks.db")
    runner = PerformanceBenchmarkRunner(db_file)

    # Hash benchmark
    hash_metric = runner.run_hash_benchmark(data_size_bytes=5 * 1024 * 1024, threshold_mbps=10.0)
    assert hash_metric.passed is True
    assert hash_metric.throughput_mbps >= 10.0

    # Carving benchmark with exact size verification
    exact_size = 2 * 1024 * 1024
    carve_metric = runner.run_carving_benchmark(data_size_bytes=exact_size, threshold_mbps=5.0)
    assert carve_metric.passed is True
    assert carve_metric.throughput_mbps >= 5.0
    assert carve_metric.duration_seconds > 0.0
    assert f"Scanned exactly {exact_size} bytes" in (carve_metric.notes or "")

    # Threshold evaluation test (unrealistically high threshold should fail)
    high_threshold_metric = runner.run_carving_benchmark(data_size_bytes=1024 * 1024, threshold_mbps=999999.0)
    assert high_threshold_metric.passed is False

    # Check metrics recorded in SQLite database
    metrics = runner.list_metrics()
    assert len(metrics) == 3
    # Verify metric persistence fields
    assert any(m.benchmark_id == carve_metric.benchmark_id for m in metrics)
    assert any(m.benchmark_id == high_threshold_metric.benchmark_id for m in metrics)


def test_validation_dossier_generation(tmp_path):
    pdf_out = str(tmp_path / "QualityAssuranceDossier.pdf")
    data = ValidationDossierGenerator.generate_dossier_data(
        safety_tests_passed=15,
        safety_tests_total=15,
        recovery_precision=0.98,
        recovery_recall=0.96,
        benchmarks=[
            {"operation_name": "SHA256_HASH", "throughput_mbps": 420.5, "threshold_mbps": 100.0, "passed": True, "duration_seconds": 0.12},
            {"operation_name": "CARVING_SCAN", "throughput_mbps": 150.2, "threshold_mbps": 50.0, "passed": True, "duration_seconds": 0.25},
        ],
        adversarial_tests=[
            {"target": "Timestomp Detection", "result": "PASS", "detected": True},
        ],
    )
    assert data["certification"] == "RELEASE_CERTIFIED"
    assert data["release_blocking_safety_passed"] is True

    ValidationDossierGenerator.render_dossier_pdf(data, pdf_out)
    assert os.path.exists(pdf_out)
    assert os.path.getsize(pdf_out) > 1000
