# Bootable Live Environment Architecture

## 1. Overview & Forensic Air-Gap Principles
The SANCTUM Bootable Live Environment provides an ephemeral, forensically pure operating system image (RAM-boot) designed for onsite digital forensics and NIST SP 800-88 enterprise media sanitization.

### Principles:
- **No Residual Footprint**: Runs completely from memory (`tmpfs` / `initramfs`). Local disks are never used for caching, swapping, or scratch operations.
- **Kernel-Level Write Blocking**: Default boot parameters mount and detect physical storage buses strictly read-only unless an authenticated capability token is issued by the Safety Guard.
- **Volatile Execution State**: System power-down permanently vaporizes all in-memory keys, plaintext sectors, and transient caches.

---

## 2. Boot Stack & Kernel Architecture
- **Base OS**: Minimalist Debian Live / Alpine Linux kernel (Linux 6.x LTS).
- **Bootloader**: Dual UEFI (x86_64 / aarch64) and Legacy BIOS with GRUB2 / Syslinux.
- **Root Filesystem**: Read-only SquashFS compressed image with `overlayfs` backed by volatile RAM.
- **Hardware Bus Drivers**: Native NVMe, AHCI/SATA, SCSI/SAS, USB-UASP, and eMMC kernel modules.

### Kernel Command Line Parameters:
```text
boot=live toram union=overlayfs ro noswap block.default_ro=1 console=tty1 console=ttyS0,115200
```
- `toram`: Copies SquashFS completely into RAM, releasing the boot USB drive so it can be safely detached.
- `noswap`: Strictly disables all swap partitions and paging files.
- `block.default_ro=1`: Enforces hardware kernel write-blocking across all discovered block devices at boot.

---

## 3. Storage Hierarchy
```text
+--------------------------------------------------------------+
|                    RAM-Only System (tmpfs)                   |
|  / (Root Overlay) -> Read-Only SquashFS + Ephemeral RAM layer |
|  /var/log/sanctum -> In-Memory Append-Only Chained Audit Log |
+--------------------------------------------------------------+
                               |
            [SANCTUM Safety Guard & DAL Controller]
                               |
    +--------------------------+--------------------------+
    |                                                     |
    v                                                     v
[Source Media - Write-Blocked]              [Target Destination Disk]
(Forensic Acquisition / Analysis)           (Case Exports & Image Files)
```

---

## 4. Onsite Deployment Procedure
1. Flash the release ISO to a dedicated USB drive:
   ```bash
   dd if=sanctum-live-v0.1.0-x86_64.iso of=/dev/sdX bs=4M status=progress conv=fsync
   ```
2. Insert USB into target workstation or server and boot via UEFI Secure Boot.
3. SANCTUM launches automatically into the accessible PyQt6 GUI wizard or headless CLI.
4. Run `sanctum selftest --full` to verify hardware write-blocking, cryptographic keys, and capability grants.
5. Perform sanitization, acquisition, or recovery operations.
6. Export signed certificates and cases to external evidentiary storage.
7. Gracefully shut down or reboot: memory is cleared immediately upon loss of power.
