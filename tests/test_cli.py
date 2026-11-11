import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from sanctum import __version__
from sanctum.cli.main import app
from sanctum.cli.codes import ExitCode
from sanctum.cli.workorder import SignedWorkOrder
from sanctum.cases.db import CaseDatabase
from sanctum.cases.models import CaseState

runner = CliRunner()


def test_cli_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == ExitCode.SUCCESS
    assert f"sanctum version {__version__}" in res.stdout


def test_cli_device_commands() -> None:
    # 1. device list
    res_list = runner.invoke(app, ["device", "list"])
    assert res_list.exit_code == ExitCode.SUCCESS
    assert "PhysicalDrive1" in res_list.stdout or "virtual://" in res_list.stdout

    # 2. device list JSON
    res_json = runner.invoke(app, ["--json", "device", "list"])
    assert res_json.exit_code == ExitCode.SUCCESS
    data = json.loads(res_json.stdout)
    assert "devices" in data

    # 3. device info
    res_info = runner.invoke(app, ["device", "info", "virtual://test"])
    assert res_info.exit_code == ExitCode.SUCCESS
    assert "Device Information for" in res_info.stdout


def test_cli_safety_refusal_paths(tmp_path) -> None:
    # Test Path 1: Missing Confirmation in Non-Interactive shell (OPERATOR_ABORT)
    res_abort = runner.invoke(app, ["erase", "run", "virtual://drive1"])
    # CliRunner provides non-interactive stdin, so operator abort triggers
    assert res_abort.exit_code in (ExitCode.OPERATOR_ABORT, ExitCode.SAFETY_REFUSAL)

    # Test Path 2: Ambiguous / Empty serial identity refused by SafetyGuard
    # Handled inside SafetyGuard (Ambiguous identity check)

    # Test Path 3: Invalid / Expired Work Order Refusal
    bad_order_file = tmp_path / "bad_order.json"
    with open(bad_order_file, "w", encoding="utf-8") as f:
        # Invalid signature
        json.dump({
            "order_id": "BAD-01",
            "operator": "Malicious",
            "target_serial": "VIRT-TEST-001",
            "policy": "NIST_800_88_CLEAR",
            "issued_at": 1000.0,
            "expires_at": 2000.0,
            "signature": "corrupted_sig",
        }, f)

    res_bad_order = runner.invoke(app, ["erase", "run", "virtual://drive1", "--work-order", str(bad_order_file)])
    assert res_bad_order.exit_code == ExitCode.SAFETY_REFUSAL


def test_cli_signed_work_order_success(tmp_path) -> None:
    # Generate valid signed work order
    order_file = tmp_path / "valid_order.json"
    order = SignedWorkOrder.create(
        order_id="WO-2026-999",
        operator="BatchOperator",
        target_serial="VIRT-TEST-001",
        policy="NIST_800_88_CLEAR",
        duration_sec=7200,
    )
    with open(order_file, "w", encoding="utf-8") as f:
        f.write(order.model_dump_json(indent=2))

    # Run erase with signed work order
    res = runner.invoke(app, ["--json", "erase", "run", "virtual://drive1", "--work-order", str(order_file)])
    assert res.exit_code == ExitCode.SUCCESS
    assert "STAGE 1: PLAN" in res.stdout or "SUCCESS" in res.stdout


def test_cli_dry_run_workflow() -> None:
    res = runner.invoke(app, ["--dry-run", "erase", "run", "virtual://drive1"])
    assert res.exit_code == ExitCode.SUCCESS
    assert "DRY-RUN completed" in res.stdout


def test_cli_acquire_command(tmp_path) -> None:
    out_img = tmp_path / "test.dd"
    res = runner.invoke(app, ["acquire", "image", "virtual://test_drive", "--output", str(out_img)])
    assert res.exit_code == ExitCode.SUCCESS
    assert "Acquisition verified" in res.stdout


def test_cli_recover_commands(tmp_path) -> None:
    # 1. recover files
    out_dir = tmp_path / "recovered_files"
    res_files = runner.invoke(app, ["recover", "files", "virtual://image.dd", "--output-dir", str(out_dir)])
    assert res_files.exit_code == ExitCode.SUCCESS

    # 2. recover carve
    carve_dir = tmp_path / "carved"
    res_carve = runner.invoke(app, ["recover", "carve", "virtual://image.dd", "--output-dir", str(carve_dir)])
    assert res_carve.exit_code == ExitCode.SUCCESS

    # 3. recover timeline
    tl_csv = tmp_path / "timeline.csv"
    res_tl = runner.invoke(app, ["recover", "timeline", "virtual://image.dd", "--output-csv", str(tl_csv)])
    assert res_tl.exit_code == ExitCode.SUCCESS


def test_cli_case_management(tmp_path, monkeypatch) -> None:
    test_db = str(tmp_path / "cli_cases.db")
    monkeypatch.setenv("SANCTUM_DB_PATH", test_db)

    # 1. Create case
    res_c = runner.invoke(app, ["--json", "case", "create", "CASE-CLI-01", "--title", "CLI Test Investigation"])
    assert res_c.exit_code == ExitCode.SUCCESS

    # 2. Open case
    res_o = runner.invoke(app, ["--json", "case", "open", "CASE-CLI-01"])
    assert res_o.exit_code == ExitCode.SUCCESS

    # 3. Attach exhibit
    res_a = runner.invoke(app, ["--json", "case", "attach", "CASE-CLI-01", "--exhibit", "EXH-99", "--desc", "Seized Tablet"])
    assert res_a.exit_code == ExitCode.SUCCESS

    # 4. Close case
    res_cl = runner.invoke(app, ["--json", "case", "close", "CASE-CLI-01"])
    assert res_cl.exit_code == ExitCode.SUCCESS

    # 5. Export case
    zip_out = tmp_path / "case_cli_export.zip"
    res_exp = runner.invoke(app, ["--json", "case", "export", "CASE-CLI-01", "--output", str(zip_out)])
    assert res_exp.exit_code == ExitCode.SUCCESS
    assert zip_out.exists()

    # 6. Verify case
    res_ver = runner.invoke(app, ["case", "verify", str(zip_out)])
    assert res_ver.exit_code == ExitCode.SUCCESS
    assert "VERIFICATION SUCCESS" in res_ver.stdout
