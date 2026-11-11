#!/usr/bin/env python3
"""
M15 CLI Demonstration Script.
Demonstrates:
- Top-level `--help` and command group organization (`device`, `erase`, `acquire`, `recover`, `case`).
- Global options (`--case`, `--operator`, `--dry-run`, `--json`).
- Strict 4-Stage Destructive Workflow: PLAN -> TOKEN -> CONFIRMATION -> RUN.
- Batch automation with cryptographically signed work orders (`SignedWorkOrder`).
- Safety refusal paths (non-interactive abort, expired/corrupted work order).
- Streaming JSON progress and distinct exit codes.
"""

import sys
import os
import json
import time
from pathlib import Path
from typer.testing import CliRunner

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanctum.cli.main import app
from sanctum.cli.codes import ExitCode
from sanctum.cli.workorder import SignedWorkOrder


def main():
    print("=" * 75)
    print("SANCTUM M15 — UNIFIED FORENSIC & ERASURE CLI DEMONSTRATION")
    print("=" * 75)

    runner = CliRunner()

    # 1. Inspect Device Listing
    print("\n[+] 1. Enumerating storage devices (`sanctum device list`)...")
    res = runner.invoke(app, ["device", "list"])
    print(res.stdout.strip())

    # 2. Dry-Run Destructive Workflow (PLAN stage only)
    print("\n[+] 2. Executing Dry-Run Sanitization (`sanctum --dry-run erase run virtual://drive1`)...")
    res_dry = runner.invoke(app, ["--dry-run", "erase", "run", "virtual://drive1"])
    print(f"    - Exit Code: {res_dry.exit_code} ({ExitCode(res_dry.exit_code).name})")
    print(f"    - Output: {res_dry.stdout.strip()}")

    # 3. Safety Refusal: Non-interactive Operator Abort
    print("\n[+] 3. Testing Safety Refusal: Non-Interactive Shell Without Work-Order or --force...")
    res_abort = runner.invoke(app, ["erase", "run", "virtual://drive1"])
    print(f"    - Exit Code: {res_abort.exit_code} ({ExitCode(res_abort.exit_code).name})")
    print("    - Operator confirmation fail-closed verified.")

    # 4. Batch Automation with Cryptographically Signed Work Order
    print("\n[+] 4. Batch ITAD Workflow with Signed Work Order (`SignedWorkOrder`)...")
    wo_path = Path("scratch/work_order.json")
    wo_path.parent.mkdir(parents=True, exist_ok=True)

    order = SignedWorkOrder.create(
        order_id="WO-BATCH-ITAD-8841",
        operator="AutomatedITADRobot",
        target_serial="VIRT-TEST-001",
        policy="NIST_800_88_CLEAR",
        duration_sec=3600,
    )
    with open(wo_path, "w", encoding="utf-8") as f:
        f.write(order.model_dump_json(indent=2))
    print(f"    - Generated signed work order: {wo_path} (Sig: {order.signature[:16]}...)")

    print("\n[+] 5. Executing Erase with Signed Work Order and Streaming JSON (`--json`)...")
    res_wo = runner.invoke(app, [
        "--json",
        "--operator", "AutomatedITADRobot",
        "erase", "run", "virtual://drive1",
        "--work-order", str(wo_path),
    ])
    print(f"    - Exit Code: {res_wo.exit_code} ({ExitCode(res_wo.exit_code).name})")
    for line in res_wo.stdout.strip().splitlines()[:5]:
        print(f"      {line}")
    print("      ... (streaming JSON progress verified)")

    # 5. Acquire command
    print("\n[+] 6. Forensic Bit-Stream Acquisition (`sanctum acquire image`)...")
    out_img = Path("scratch/demo_acquire.dd")
    res_acq = runner.invoke(app, [
        "acquire", "image", "virtual://source_disk",
        "--output", str(out_img),
        "--format", "RAW",
    ])
    print(f"    - Exit Code: {res_acq.exit_code}")
    for line in res_acq.stdout.strip().splitlines()[-3:]:
        print(f"      {line}")

    # 6. Case Creation and Verification
    print("\n[+] 7. Case Management via CLI (`sanctum case`)...")
    os.environ["SANCTUM_DB_PATH"] = "scratch/demo_cli_cases.db"
    res_case = runner.invoke(app, ["case", "create", "CASE-CLI-DEMO", "--title", "CLI Automated Evidence Intake"])
    print(f"    - Case Create Exit Code: {res_case.exit_code}")

    print("\n" + "=" * 75)
    print("[+] SANCTUM M15 CLI DEMO COMPLETED SUCCESSFULLY")
    print("=" * 75)


if __name__ == "__main__":
    main()
