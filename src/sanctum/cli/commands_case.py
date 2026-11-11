import typer
from pathlib import Path
from typing import Optional

from sanctum.cli.codes import ExitCode
from sanctum.cli.context import CLIContext
from sanctum.cases.db import CaseDatabase
from sanctum.cases.models import CaseState
from sanctum.cases.export import CaseExporter

app = typer.Typer(help="Forensic case database management, custody records, and export.")


def _get_db() -> CaseDatabase:
    import os
    db_file = os.getenv("SANCTUM_DB_PATH", "sanctum_cases.db")
    return CaseDatabase(str(db_file))


@app.command("create")
def case_create(
    ctx: typer.Context,
    case_number: str = typer.Argument(..., help="Unique case identifier"),
    title: str = typer.Option(..., "--title", "-t", help="Case descriptive title"),
    agency: Optional[str] = typer.Option(None, "--agency", help="Investigating agency"),
) -> None:
    """Create a new forensic case in CREATED state."""
    cli_ctx: CLIContext = ctx.obj
    db = _get_db()
    case = db.create_case(
        case_number=case_number,
        title=title,
        investigator=cli_ctx.operator,
        agency=agency,
    )
    cli_ctx.emit_result({
        "status": "SUCCESS",
        "case_id": case.case_id,
        "case_number": case.case_number,
        "state": case.state.value,
        "created_at": case.created_at,
    })


@app.command("open")
def case_open(
    ctx: typer.Context,
    case_number: str = typer.Argument(..., help="Case number to open"),
) -> None:
    """Transition case lifecycle to OPEN state."""
    cli_ctx: CLIContext = ctx.obj
    db = _get_db()
    case = db.get_case(case_number)
    if not case:
        typer.secho(f"Case {case_number} not found.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.GENERAL_ERROR)
    case = db.transition_state(case.case_id, CaseState.OPEN)
    cli_ctx.emit_result({
        "status": "SUCCESS",
        "case_number": case.case_number,
        "state": case.state.value,
    })


@app.command("attach")
def case_attach(
    ctx: typer.Context,
    case_number: str = typer.Argument(..., help="Target case number"),
    exhibit_number: str = typer.Option(..., "--exhibit", "-e", help="Exhibit reference number"),
    description: str = typer.Option(..., "--desc", "-d", help="Exhibit description"),
    serial: Optional[str] = typer.Option(None, "--serial", "-s", help="Hardware serial number"),
) -> None:
    """Attach evidence exhibit to case in ATTACH_EXHIBIT state."""
    cli_ctx: CLIContext = ctx.obj
    db = _get_db()
    case = db.get_case(case_number)
    if not case:
        typer.secho(f"Case {case_number} not found.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.GENERAL_ERROR)

    if case.state == CaseState.OPEN:
        case = db.transition_state(case.case_id, CaseState.ATTACH_EXHIBIT)

    exhibit = db.add_exhibit(
        case_id=case.case_id,
        exhibit_number=exhibit_number,
        description=description,
        device_serial=serial,
        received_from=cli_ctx.operator,
    )
    if serial:
        db.register_device(serial=serial, case_id=case.case_id, exhibit_id=exhibit.exhibit_id, is_forensic_hold=True)

    cli_ctx.emit_result({
        "status": "SUCCESS",
        "case_number": case.case_number,
        "exhibit_id": exhibit.exhibit_id,
        "exhibit_number": exhibit.exhibit_number,
        "device_serial": serial,
    })


@app.command("close")
def case_close(
    ctx: typer.Context,
    case_number: str = typer.Argument(..., help="Case number to close"),
) -> None:
    """Transition case to CLOSED state."""
    cli_ctx: CLIContext = ctx.obj
    db = _get_db()
    case = db.get_case(case_number)
    if not case:
        typer.secho(f"Case {case_number} not found.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.GENERAL_ERROR)
    if case.state == CaseState.ATTACH_EXHIBIT:
        case = db.transition_state(case.case_id, CaseState.PROCESS)
    case = db.transition_state(case.case_id, CaseState.CLOSED)
    cli_ctx.emit_result({
        "status": "SUCCESS",
        "case_number": case.case_number,
        "state": case.state.value,
        "closed_at": case.closed_at,
    })


@app.command("export")
def case_export(
    ctx: typer.Context,
    case_number: str = typer.Argument(..., help="Case number to export"),
    output_zip: Path = typer.Option(..., "--output", "-o", help="Destination export .zip path"),
) -> None:
    """Export self-contained forensic case package with reports, manifest, and hashes."""
    cli_ctx: CLIContext = ctx.obj
    db = _get_db()
    case = db.get_case(case_number)
    if not case:
        typer.secho(f"Case {case_number} not found.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.GENERAL_ERROR)

    manifest = CaseExporter.export_case(
        case_db=db,
        case_id=case.case_id,
        export_zip_path=str(output_zip),
    )
    cli_ctx.emit_result({
        "status": "SUCCESS",
        "export_archive": str(output_zip),
        "manifest_summary": {
            "case_number": case.case_number,
            "exhibits": len(manifest.get("exhibits", [])),
            "recovered_objects": manifest.get("recovered_objects_count", 0),
        },
    })


@app.command("verify")
def case_verify(
    ctx: typer.Context,
    archive_path: Path = typer.Argument(..., help="Exported case .zip file to verify"),
) -> None:
    """Independently verify an exported forensic case package."""
    cli_ctx: CLIContext = ctx.obj
    res = CaseExporter.verify_exported_case(str(archive_path))
    if res["valid"]:
        cli_ctx.emit_result({
            "status": "SUCCESS",
            "verified_files": res["verified_files"],
            "custody_intact": res["custody_intact"],
            "details": res["manifest_details"],
        }, plain_text="VERIFICATION SUCCESS: All cryptographic hashes and chain of custody are intact.")
    else:
        typer.secho("VERIFICATION FAILURE: Integrity violations found!", fg=typer.colors.RED, err=True)
        for err in res["errors"]:
            typer.echo(f"  [!] {err}", err=True)
        raise typer.Exit(code=ExitCode.VERIFICATION_FAILURE)
