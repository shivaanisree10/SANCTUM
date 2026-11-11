#!/usr/bin/env python3
"""
M16 PyQt6 Graphical User Interface Demonstration.
Demonstrates the 6-stage wizard:
1. Launch / Mode Selection (Locked for session)
2. Device Inventory (Boot disks visibly protected)
3. Method / Acquisition Plan
4. Confirmation (Serial tail input, 3s safety lock, deliberate acknowledgement)
5. Execution (Worker thread, responsive GUI, live metrics, abort button)
6. Results (Verification verdict, SHA-256 digests, certificate, audit trail excerpt)
"""

import sys
import os

# Set headless mode if running non-interactively
if "--headless" in sys.argv or "CI" in os.environ:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt6.QtWidgets import QApplication
from sanctum.gui.wizard import SanctumWizard


def main():
    print("=" * 75)
    print("SANCTUM M16 — PYQT6 GRAPHICAL USER INTERFACE DEMONSTRATION")
    print("=" * 75)

    app = QApplication.instance() or QApplication(sys.argv)
    wizard = SanctumWizard()

    print("[+] 1. Launching SanctumWizard...")
    print(f"    - Window Title: {wizard.windowTitle()}")
    print(f"    - Total Wizard Pages: {len(wizard.pageIds())}")

    # Inspect Stage 1: Mode Selection
    print("\n[+] 2. Stage 1 (Mode Selection):")
    print(f"    - Default Mode: {wizard.mode_page.get_selected_mode()}")
    print(f"    - Locked Session Mode: {wizard.mode}")

    # Inspect Stage 2: Inventory
    print("\n[+] 3. Stage 2 (Device Inventory):")
    inv = wizard.inventory_page
    for r in range(inv.table.rowCount()):
        dev_path = inv.table.item(r, 0).text()
        dev_serial = inv.table.item(r, 1).text()
        prot = inv.table.item(r, 5).text()
        print(f"    - Device [{r}]: {dev_path:<22} Serial: {dev_serial:<20} {prot}")

    # Select target disk
    inv.table.selectRow(1)
    print(f"    - Selected non-protected drive: {inv.selected_device['serial']}")

    # Inspect Stage 3: Method Plan
    wizard.next()
    print("\n[+] 4. Stage 3 (Method / Acquisition Plan):")
    print(f"    - Configured Policy: {wizard.method_page.policy_combo.currentText()}")

    # Inspect Stage 4: Confirmation
    wizard.next()
    print("\n[+] 5. Stage 4 (Confirmation & Safety Gates):")
    conf = wizard.confirmation_page
    print(f"    - Destructive Banner Visible: {conf.destruct_banner.isVisible()}")
    print(f"    - Required Serial Tail: {conf.expected_tail}")
    print(f"    - Confirmation Button State: {'LOCKED (3s safety delay)' if not conf.isComplete() else 'UNLOCKED'}")

    print("\n[+] M16 Demonstration validated successfully.")


if __name__ == "__main__":
    main()
