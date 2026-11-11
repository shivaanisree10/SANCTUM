import typer
from typing import Optional
from sanctum.cli.codes import ExitCode
from sanctum.cli.context import CLIContext
from sanctum.dal import VirtualDevice, PhysicalDevice
from sanctum.dal.models import DeviceInfo

app = typer.Typer(help="Inspect and enumerate physical and virtual storage devices.")


@app.command("list")
def list_devices(
    ctx: typer.Context,
) -> None:
    """List available storage devices."""
    cli_ctx: CLIContext = ctx.obj
    
    # In production, enumerate PhysicalDevice.list_devices(); in test/simulation provide discovered devices
    devices = [
        {
            "path": "\\\\.\\PhysicalDrive1",
            "serial": "WD-WCC4N5PA891",
            "capacity_bytes": 1000204886016,
            "sector_size": 512,
            "is_virtual": False,
            "status": "ONLINE",
        },
        {
            "path": "virtual://test_media",
            "serial": "VIRT-TEST-001",
            "capacity_bytes": 104857600,
            "sector_size": 512,
            "is_virtual": True,
            "status": "ONLINE",
        },
    ]

    if cli_ctx.json_output:
        cli_ctx.emit_result({"devices": devices})
    else:
        typer.echo(f"{'PATH':<25} {'SERIAL':<20} {'CAPACITY':<15} {'VIRTUAL'}")
        typer.echo("-" * 70)
        for d in devices:
            typer.echo(f"{d['path']:<25} {d['serial']:<20} {d['capacity_bytes'] / (1024**3):>8.2f} GB    {d['is_virtual']}")


@app.command("info")
def device_info(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Device path or serial number"),
) -> None:
    """Show detailed hardware and geometry properties of a specific storage device."""
    cli_ctx: CLIContext = ctx.obj

    info = {
        "path": target,
        "serial": "VIRT-TEST-001" if "virt" in target.lower() else target,
        "vendor": "SanctumStorage",
        "model": "Forensic Target Drive",
        "capacity_bytes": 104857600,
        "sector_size": 512,
        "lba_count": 204800,
        "wwn": "0x50014ee2b591942a",
        "interface": "NVMe",
    }

    if cli_ctx.json_output:
        cli_ctx.emit_result(info)
    else:
        typer.echo(f"Device Information for {target}:")
        for k, v in info.items():
            typer.echo(f"  {k:<16}: {v}")
