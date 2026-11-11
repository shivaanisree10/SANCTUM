import typer
from sanctum import __version__
from sanctum.logging import setup_logging
from sanctum.config import load_config
from pathlib import Path
import logging
from typing import Optional

from sanctum.cli.codes import ExitCode
from sanctum.cli.context import CLIContext
from sanctum.cli.commands_device import app as device_app
from sanctum.cli.commands_erase import app as erase_app
from sanctum.cli.commands_acquire import app as acquire_app
from sanctum.cli.commands_recover import app as recover_app
from sanctum.cli.commands_case import app as case_app

app = typer.Typer(
    name="sanctum",
    help="SANCTUM: Unified High-Assurance Data Destruction & Forensic Recovery Platform",
    no_args_is_help=True,
)

# Attach the 5 command groups
app.add_typer(device_app, name="device")
app.add_typer(erase_app, name="erase")
app.add_typer(acquire_app, name="acquire")
app.add_typer(recover_app, name="recover")
app.add_typer(case_app, name="case")


@app.callback()
def main_callback(
    ctx: typer.Context,
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Associate operation with a case number"),
    operator: str = typer.Option("Examiner", "--operator", help="Operator or investigator identity"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate operation without altering evidence/media"),
    json_output: bool = typer.Option(False, "--json", help="Stream progress and output in JSON format"),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level (DEBUG, INFO, WARNING, ERROR)"),
    config: str = typer.Option("config.yaml", "--config", help="Path to Sanctum configuration file"),
) -> None:
    """Global configuration and options for Sanctum CLI."""
    setup_logging(log_level)
    logger = logging.getLogger("sanctum")

    # Initialize CLIContext
    ctx.obj = CLIContext(
        case_number=case,
        operator=operator,
        dry_run=dry_run,
        json_output=json_output,
        log_level=log_level,
        config_path=config,
    )


@app.command("version")
def version() -> None:
    """Print the version of sanctum."""
    typer.echo(f"sanctum version {__version__}")


@app.command("verify-case")
def verify_case(archive_path: str = typer.Argument(..., help="Path to exported case zip archive")) -> None:
    """Independently verify a self-contained exported forensic case archive."""
    from sanctum.cases.export import CaseExporter
    typer.echo(f"Verifying exported case: {archive_path}")
    res = CaseExporter.verify_exported_case(archive_path)
    if res["valid"]:
        typer.secho("VERIFICATION SUCCESS: All files and chain-of-custody hashes intact.", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho("VERIFICATION FAILED: Integrity violation detected!", fg=typer.colors.RED, bold=True)
        for err in res["errors"]:
            typer.echo(f"  [!] {err}")
        raise typer.Exit(code=ExitCode.VERIFICATION_FAILURE)


@app.command("selftest")
def selftest(
    ctx: typer.Context,
    full: bool = typer.Option(True, "--full", help="Execute complete release-blocking validation self-test"),
) -> None:
    """Run comprehensive platform integrity, capability, and safety self-test."""
    from sanctum.testing.selftest import SelfTestRunner
    cli_ctx: CLIContext = ctx.obj

    if not full:
        typer.echo("Executing standard self-test...")

    typer.echo("Running SANCTUM Full Platform Self-Test...")
    res = SelfTestRunner.run_full_selftest(verbose=True)

    if cli_ctx and cli_ctx.json_output:
        cli_ctx.emit_result(res)
    else:
        for chk in res["checks"]:
            status_text = "[PASS]" if chk["status"] == "PASS" else "[FAIL]"
            color = typer.colors.GREEN if chk["status"] == "PASS" else typer.colors.RED
            typer.secho(f"  {status_text} {chk['name']:<35} : {chk['details']}", fg=color)
        
        if res["status"] == "PASS":
            typer.secho("\nSELF-TEST SUCCESS: All security, capability, and safety gates verified.", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho("\nSELF-TEST FAILURE: Release-blocking checks failed!", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=ExitCode.SAFETY_REFUSAL)


if __name__ == "__main__":
    app()
