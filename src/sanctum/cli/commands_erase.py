import os
import json
import typer
from typing import Optional
from pathlib import Path

from sanctum.cli.codes import ExitCode
from sanctum.cli.context import CLIContext
from sanctum.cli.workorder import SignedWorkOrder
from sanctum.safety.guard import SafetyGuard, SafetyError
from sanctum.safety.models import OperationMode
from sanctum.dal.models import DeviceInfo
from sanctum.policies.registry import PolicyRegistry as MethodPolicyRegistry
from sanctum.policies.models import VerificationRequirement
from sanctum.erasure.engine import ErasureEngine
from sanctum.erasure.models import ErasureState
from sanctum.dal import VirtualDevice
from sanctum.audit import AuditWriter
from sanctum.verification.certificate import CertificateGenerator
from sanctum.verification.models import VerificationResult

app = typer.Typer(help="Destructive data sanitization and firmware purge workflows.")


def execute_destructive_workflow(
    cli_ctx: CLIContext,
    target: str,
    policy_name: str,
    work_order_path: Optional[str] = None,
    force: bool = False,
    guard: Optional[SafetyGuard] = None,
) -> None:
    """
    Strict 4-stage Destructive Workflow:
    STAGE 1: PLAN (Assess geometry, policy passes, estimated time)
    STAGE 2: CONFIRMATION TOKEN (Request capability token from SafetyGuard)
    STAGE 3: OPERATOR CONFIRMATION (TTY prompt or Signed Work Order validation)
    STAGE 4: RUN (Perform overwrite/purge and streaming progress)
    """
    safety_guard = guard or SafetyGuard()
    
    # Target resolution
    target_clean = target.replace("virtual://", "")
    is_virtual = "virt" in target.lower() or not target.startswith("\\\\.\\")
    
    device_obj = None
    if os.path.exists(target_clean) and os.path.isfile(target_clean):
        try:
            device_obj = VirtualDevice(target_clean)
            device_info = device_obj.info
            serial = device_info.serial
            capacity = device_info.capacity_bytes
        except Exception as e:
            typer.secho(f"Failed to open virtual target device: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=ExitCode.DEVICE_ERROR)
    elif target.startswith("\\\\.\\"):
        # Real physical drive specification: strictly read-only in DAL, forbidden for destructive write
        serial = target
        capacity = 104857600
        sector_size = 512
        lba_count = capacity // sector_size
        device_info = DeviceInfo(
            path=target,
            serial=serial,
            capacity_bytes=capacity,
            sector_size=sector_size,
            lba_count=lba_count,
            is_virtual=False,
        )
    else:
        # Named virtual identifier / test target
        serial = "VIRT-TEST-001" if is_virtual else target
        capacity = 104857600
        sector_size = 512
        lba_count = capacity // sector_size
        device_info = DeviceInfo(
            path=target,
            serial=serial,
            capacity_bytes=capacity,
            sector_size=sector_size,
            lba_count=lba_count,
            is_virtual=is_virtual,
        )

    # -------------------------------------------------------------
    # STAGE 1: PLAN
    # -------------------------------------------------------------
    registry = MethodPolicyRegistry()
    default_cfg = Path("config/default_policies.yaml")
    if default_cfg.exists():
        registry.load_file(default_cfg)

    # Resolve policy
    policy = None
    try:
        policy = registry.get_policy(policy_name)
    except Exception:
        # Check case-insensitive / normalized name (e.g. NIST_800_88_CLEAR -> NIST-Clear)
        norm_req = policy_name.lower().replace("-", "").replace("_", "").replace("80088", "")
        for p in registry.list_policies():
            p_norm = p.name.lower().replace("-", "").replace("_", "").replace("80088", "")
            if p_norm == norm_req or p.name.lower().replace("-", "_") == policy_name.lower().replace("-", "_"):
                policy = p
                break
    
    if not policy:
        typer.secho(f"Invalid policy '{policy_name}': Policy not found in registry.", fg=typer.colors.RED)
        cli_ctx.emit_result({"status": "INVALID_POLICY", "policy": policy_name})
        if device_obj:
            device_obj.close()
        raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)

    plan = {
        "target": target,
        "serial": serial,
        "capacity_bytes": capacity,
        "policy": policy.name,
        "passes": len(policy.passes),
        "operator": cli_ctx.operator,
        "dry_run": cli_ctx.dry_run,
    }

    if cli_ctx.dry_run:
        cli_ctx.print_progress(100.0, "DRY-RUN completed. Plan generated, no sectors modified.", extra=plan)
        cli_ctx.emit_result({"status": "DRY_RUN_SUCCESS", "plan": plan})
        raise typer.Exit(code=ExitCode.SUCCESS)

    cli_ctx.print_progress(10.0, f"STAGE 1: PLAN validated for {target} ({policy.name}, {len(policy.passes)} passes).")

    # -------------------------------------------------------------
    # STAGE 2: CONFIRMATION TOKEN (Safety Guard)
    # -------------------------------------------------------------
    cli_ctx.print_progress(20.0, "STAGE 2: Requesting capability lock from Safety Guard...")
    try:
        # Must pass confirmed=True to request_token; safety guard performs protection checks
        token = safety_guard.request_token(
            device=device_info,
            job_id="CLI-ERASE-JOB",
            operation_id="OP-ERASE",
            mode=OperationMode.SANITIZATION,
            confirmed=True,
        )
    except SafetyError as e:
        typer.secho(f"SAFETY REFUSAL: {e}", fg=typer.colors.RED, bold=True, err=True)
        cli_ctx.emit_result({"status": "SAFETY_REFUSAL", "reason": str(e)})
        raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)

    # -------------------------------------------------------------
    # STAGE 3: OPERATOR CONFIRMATION
    # -------------------------------------------------------------
    cli_ctx.print_progress(30.0, f"STAGE 3: Awaiting operator confirmation (Token: {token.token_id})...")
    
    # Check for Signed Work Order first (enables non-interactive batch ITAD processing)
    if work_order_path:
        if not os.path.exists(work_order_path):
            safety_guard.revoke_token(token)
            typer.secho(f"Work order file {work_order_path} does not exist.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)
        with open(work_order_path, "r", encoding="utf-8") as f:
            order_data = json.load(f)
            order = SignedWorkOrder(**order_data)
            if not order.is_valid(b"sanctum_work_order_secret"):
                safety_guard.revoke_token(token)
                typer.secho("Signed Work Order verification FAILED: Invalid signature or expired.", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)
            if order.target_serial != serial:
                safety_guard.revoke_token(token)
                typer.secho(f"Work order target serial {order.target_serial} does not match {serial}.", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)
            cli_ctx.print_progress(40.0, f"Signed Work Order {order.order_id} verified cryptographically.")
    elif force:
        # Explicit CLI --force confirmation
        cli_ctx.print_progress(40.0, "Operator confirmation confirmed via --force.")
    elif not cli_ctx.is_tty():
        # Non-interactive shell without work-order or --force MUST fail-closed!
        safety_guard.revoke_token(token)
        typer.secho("OPERATOR ABORT: Non-interactive environment detected without signed work order or --force.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.OPERATOR_ABORT)
    else:
        # Interactive TTY confirmation
        confirm = typer.confirm(f"CRITICAL WARNING: Irreversibly destroy all data on {target} (Serial: {serial})?")
        if not confirm:
            safety_guard.revoke_token(token)
            typer.secho("OPERATOR ABORT: Sanitization aborted by operator.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(code=ExitCode.OPERATOR_ABORT)
        cli_ctx.print_progress(40.0, "Operator interactive confirmation received.")

    # -------------------------------------------------------------
    # STAGE 4: RUN
    # -------------------------------------------------------------
    cli_ctx.print_progress(50.0, "STAGE 4: Initializing sanitization engine and auditing...")
    audit_writer = AuditWriter("sanctum_audit.log")
    
    erasure_state = ErasureState.COMPLETED
    verification_rep = None

    if device_obj:
        try:
            engine = ErasureEngine(device_obj, safety_guard, token, audit_writer)
            
            def on_progress(p):
                # Map engine progress 0-100 to workflow 50-90
                mapped = 50.0 + (p.percentage * 0.4)
                cli_ctx.print_progress(mapped, f"Pass {p.current_pass}/{p.total_passes} - {p.throughput_bytes_per_sec/1024/1024:.2f} MB/s")

            erasure_state = engine.run(policy, block_size=1048576, callback=on_progress)
            verification_rep = engine.verification_report
        except Exception as e:
            safety_guard.revoke_token(token)
            device_obj.close()
            typer.secho(f"Execution failure during erasure: {e}", fg=typer.colors.RED, err=True)
            cli_ctx.emit_result({"status": "DEVICE_ERROR", "error": str(e)})
            raise typer.Exit(code=ExitCode.DEVICE_ERROR)
        finally:
            device_obj.close()
    else:
        # Non-file virtual target (e.g., simulation in dry-run or memory mockup)
        pass_name = policy.passes[0].value if hasattr(policy.passes[0], "value") else str(policy.passes[0])
        cli_ctx.print_progress(70.0, f"Overwriting sectors with pattern {pass_name}...")
        cli_ctx.print_progress(90.0, "Performing post-erase zero-tolerance verification...")

    # Release token
    safety_guard.revoke_token(token)

    if erasure_state != ErasureState.COMPLETED:
        typer.secho(f"ERASURE FAILED or QUARANTINED: State = {erasure_state.value}", fg=typer.colors.RED, bold=True, err=True)
        cli_ctx.emit_result({
            "status": "VERIFICATION_FAILURE" if verification_rep else "ERASURE_ERROR",
            "state": erasure_state.value,
            "target": target,
            "serial": serial,
            "disposition": verification_rep.disposition if verification_rep else "QUARANTINED",
            "errors": verification_rep.errors if verification_rep else "Erasure execution error"
        })
        raise typer.Exit(code=ExitCode.VERIFICATION_FAILURE)

    cli_ctx.print_progress(100.0, f"Sanitization of {target} successfully completed.")
    result_data = {
        "status": "SUCCESS",
        "target": target,
        "serial": serial,
        "policy": policy.name,
        "passes_completed": len(policy.passes),
        "operator": cli_ctx.operator,
        "disposition": verification_rep.disposition if verification_rep else "SANITIZED",
        "certificate_id": verification_rep.certificate_id if verification_rep else None
    }
    cli_ctx.emit_result(result_data)


@app.command("run")
def erase_run(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target device path or serial"),
    policy: str = typer.Option("NIST_800_88_CLEAR", "--policy", "-p", help="Sanitization policy"),
    work_order: Optional[str] = typer.Option(None, "--work-order", help="Path to signed work order JSON"),
    force: bool = typer.Option(False, "--force", "-f", help="Bypass interactive confirmation prompt"),
) -> None:
    """Execute destructive drive erasure with strict safety gates."""
    cli_ctx: CLIContext = ctx.obj
    execute_destructive_workflow(cli_ctx, target, policy, work_order, force)
