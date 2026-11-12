# SANCTUM

Integrated Secure data erasure and file recovery tool

## Requirements
- Python 3.11+
- Windows (for the provided test lab scripts)

## Setup

1. Create a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   pip install -e .[dev]
   ```

## Development

- **Formatting:** `black src tests`
- **Linting:** `ruff check src tests`
- **Type Checking:** `mypy src`
- **Tests:** `pytest tests/`

## Test Lab

To generate disposable test media (sparse files) for testing:

```powershell
.\scripts\create_test_media.ps1
```

To clean up:

```powershell
.\scripts\cleanup_test_media.ps1
```

## Running

```powershell
sanctum --version
```
