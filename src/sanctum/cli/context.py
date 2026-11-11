import sys
import json
import typer
from typing import Optional, Any, Dict
from pydantic import BaseModel


class CLIContext(BaseModel):
    case_number: Optional[str] = None
    operator: str = "Examiner"
    dry_run: bool = False
    json_output: bool = False
    log_level: str = "INFO"
    config_path: str = "config.yaml"

    def is_tty(self) -> bool:
        """Detects if stdin and stdout are interactive terminals."""
        return sys.stdin.isatty() and sys.stdout.isatty()

    def print_progress(self, percent: float, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Emits progress either as streaming JSON or clean terminal progress."""
        if self.json_output:
            payload = {
                "type": "progress",
                "percent": round(percent, 2),
                "message": message,
                "extra": extra or {},
            }
            typer.echo(json.dumps(payload))
        else:
            typer.echo(f"[{percent:5.1f}%] {message}")

    def emit_result(self, data: Dict[str, Any], plain_text: Optional[str] = None) -> None:
        """Emits the final command output."""
        if self.json_output:
            typer.echo(json.dumps(data, indent=2))
        elif plain_text:
            typer.echo(plain_text)
        else:
            for k, v in data.items():
                typer.echo(f"{k}: {v}")
