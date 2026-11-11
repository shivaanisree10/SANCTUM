# SANCTUM Enterprise Platform Release Documentation

Version: 0.1.0-RELEASE  
Release Date: 2026-10-19  
Build Status: RELEASE_CERTIFIED  
Verification: All 107 Unit and Integration Tests Green  

---

## 1. Changelog (M0 through M18)
- **M0 Scaffold & Configuration**: Modular architecture, structured logging, typed configuration, and Typer CLI foundation.
- **M1 Data Access Layer (DAL)**: Safe cross-platform block device abstractions, virtual test media, and physical Windows/Linux drives.
- **M2 Safety Guard & Token Lock Manager**: Fail-closed capability token management, boot drive protection, and concurrency locks.
- **M3 Tamper-Evident Chained Audit Logging**: SHA-256 HMAC cryptographic hash chaining for evidentiary compliance.
- **M4 Overwrite Engine**: Deterministic pattern generation (Zero, Ones, Pseudo-random, Gutmann), pause/resume, and abort.
- **M5 Method Policy Registry**: External YAML policies (NIST SP 800-88, DoD 5220.22-M, Gutmann) and execution time estimator.
- **M6 Firmware Sanitization**: ATA Secure Erase, NVMe Format/Sanitize (Crypto Erase, Block Erase), and SCSI/SAS Purge prototypes.
- **M7 Verification & Cryptographic Certificates**: Read-back verification, deterministic reconstruction, PDF/A certificates, and HMAC signatures.
- **M8 Acquisition & Software Write-Blocking**: RAW, E01, and AFF4 forensic imaging, error-tolerant sector substitution, and source re-hashing.
- **M9 Partition & Volume Mapper**: MBR, GPT, and hybrid partition tables, backup GPT recovery, and virtual read-only volume mounts.
- **M10 Filesystem Parser Framework**: TSK plugin integration, native FAT, NTFS ($UsnJrnl, $LogFile), ext4 (JBD2 journal), and APFS.
- **M11 Deleted File Reconstruction**: Parent-path tracing, $OrphanFiles recovery, cluster chain contiguity inference, and recovery grading.
- **M12 File Carving Engine**: Streaming Aho-Corasick multi-pattern scanner (`signatures.yaml`), Shannon entropy, and bifragment recovery.
- **M13 Metadata & Unified Forensic Timeline**: Timestamp extraction (MACB), NTFS timestomp detection ($SI vs $FN), EXIF/GPS, Office docProps, PDF metadata, and CSV timeline exports.
- **M14 Case Database & Reporting**: SQLite WAL case database, hash-chained chain of custody, PDF/A compliance reports, and portable case export/verification.
- **M15 Command-Line Interface (CLI)**: 5 unified command groups (`device`, `erase`, `acquire`, `recover`, `case`), 4-stage destructive workflow, and signed work order batch processing.
- **M16 Graphical User Interface (GUI)**: Accessible PyQt6 6-stage wizard, session mode locking, boot disk protection, and serial tail confirmation gates.
- **M17 Test Harness & Validation Suite**: Known-answer test corpus, chaos fault injector, parser fuzzing, benchmark runner, and validation dossiers.
- **M18 Packaging & Deployment**: Reproducible builds, PyInstaller spec, signed release manifests, bootable live environment architecture, and `sanctum selftest --full`.

---

## 2. Known Defects & Limitations
1. **Physical Drive Direct Access on Windows**: Direct physical drive writes require elevated Administrator / SeManageVolumePrivilege rights. Running without Administrator rights will automatically restrict DAL to virtual test media.
2. **PyTSK3 Native Binaries**: On Windows environments without C++ build tools, fallback native Python parsers are automatically engaged for FAT and NTFS analysis.
3. **Non-Interactive Silent Update Restriction**: In compliance with forensic strictness rules, **no silent automatic updates are implemented**. All updates must be explicitly invoked, verified, and authorized by the operator.

---

## 3. Installation Procedure
### Prerequisites
- Python 3.11+ (tested on Python 3.14 x86_64)
- Platform Dependencies: `pydantic`, `typer`, `PyQt6`, `fpdf2`, `qrcode`, `pyyaml`

### Development / Editable Installation
```bash
git clone https://github.com/sanctum-forensics/sanctum.git
cd sanctum
python -m pip install -e .
python -m pip install fpdf2 qrcode pyyaml PyQt6
```

### Standalone Binary Execution
Download the standalone executable and verify the cryptographic signature:
```bash
# Verify release manifest integrity
python packaging/release.py
# Run self-test
sanctum selftest --full
```

---

## 4. Explicit Update Procedures
Automatic silent background updates are strictly prohibited to maintain courtroom chain-of-custody validity.

### Manual Update Steps:
1. Operator downloads the new release archive and detached signature file (`release_manifest.json.sig`).
2. Verify the cryptographic release signature against the official master key.
3. Replace the existing executable in a non-operational state.
4. Execute full platform self-test:
   ```bash
   sanctum selftest --full
   ```
5. An audit entry recording the tool upgrade is automatically appended to the chained audit log.

---

## 5. Security & System Hardening Guidelines
1. **Forensic Air-Gapping**: Always operate within an isolated, non-networked environment when analyzing sensitive evidence or sanitizing classified media.
2. **Write-Block Verification**: Verify write counters (`sanctum acquire image`) prior to and following any acquisition task.
3. **Operator Identity Binding**: Ensure each operator utilizes their specific identifier (`--operator <name>`) to ensure non-repudiation in chained audit logs.
4. **Physical Tamper Seals**: Keep physical evidence locked in secure storage until formally checked out via `sanctum case attach`.
