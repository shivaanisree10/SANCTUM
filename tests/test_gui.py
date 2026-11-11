import os
import pytest
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

# Force offscreen QPA for headless CI / unit testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from sanctum.gui.wizard import SanctumWizard
from sanctum.gui.worker import ExecutionWorker


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_gui_wizard_initialization(qapp):
    wizard = SanctumWizard()
    assert wizard.pageIds() == [0, 1, 2, 3, 4, 5]
    assert wizard.windowTitle() == "SANCTUM Platform — Forensic Recovery & Sanitization Wizard"


def test_gui_mode_locking(qapp):
    wizard = SanctumWizard()
    # Initially mode is sanitization
    wizard.mode_page.radio_sanitize.setChecked(True)
    mode1 = wizard.mode
    assert mode1 == "SANITIZATION"

    # Mode must lock for the entire session
    wizard.mode_page.radio_acquire.setChecked(True)
    mode2 = wizard.mode
    assert mode2 == "SANITIZATION"  # Still locked to SANITIZATION


def test_gui_device_inventory_protection(qapp):
    wizard = SanctumWizard()
    inv_page = wizard.inventory_page

    # Verify that row 0 (system boot disk) is marked protected and cannot be selected as target
    prot_item = inv_page.table.item(0, 5)
    assert "[PROTECTED SYSTEM DISK]" in prot_item.text()

    # Selecting system drive should not set selected_device
    inv_page.table.selectRow(0)
    assert inv_page.selected_device is None
    assert inv_page.isComplete() is False

    # Selecting non-protected drive (e.g. PhysicalDrive1 or virtual)
    inv_page.table.selectRow(1)
    assert inv_page.selected_device is not None
    assert inv_page.selected_device["serial"] == "WD-WCC4N5PA891"
    assert inv_page.isComplete() is True


def test_gui_confirmation_safety_gates(qapp):
    wizard = SanctumWizard()
    # Select non-protected device
    wizard.inventory_page.table.selectRow(1)
    dev = wizard.inventory_page.selected_device

    conf_page = wizard.confirmation_page
    conf_page.initializePage()

    # Invariant 1: Initially incomplete due to 3-second safety lock
    assert conf_page.isComplete() is False
    assert conf_page.timer_unlocked is False

    # Simulate timer unlocking
    conf_page._on_timer_unlocked()
    assert conf_page.timer_unlocked is True
    # Still incomplete because serial tail has not been entered
    assert conf_page.isComplete() is False

    # Enter wrong serial tail
    conf_page.serial_tail_input.setText("9999")
    conf_page._validate_input()
    assert conf_page.isComplete() is False

    # Enter correct serial tail (last 4 chars of "WD-WCC4N5PA891" -> "A891")
    expected_tail = conf_page.expected_tail
    conf_page.serial_tail_input.setText(expected_tail)
    conf_page.acknowledgement_checkbox.setChecked(True)
    conf_page._validate_input()

    # Now passes confirmation gate
    assert conf_page.isComplete() is True


def test_gui_worker_execution_and_abort(qapp):
    worker = ExecutionWorker(
        mode="SANITIZATION",
        device_serial="VIRT-TEST-001",
        device_capacity=1048576,
        policy_or_format="NIST-Clear",
        operator="TestOperator",
    )

    received_progress = []
    worker.progress_changed.connect(lambda p: received_progress.append(p))

    # Test abort
    worker.abort()
    assert worker._is_aborted is True


def test_gui_recovery_workflow_and_verdict(qapp, tmp_path):
    wizard = SanctumWizard()
    wizard.mode_page.radio_recovery.setChecked(True)
    assert wizard.mode == "RECOVERY"

    # Select virtual media
    wizard.inventory_page.table.selectRow(2)
    assert wizard.inventory_page.selected_device is not None

    # Confirmation
    conf = wizard.confirmation_page
    conf.initializePage()
    conf._on_timer_unlocked()
    conf.serial_tail_input.setText(conf.expected_tail)
    assert conf.isComplete() is True

    # Execution with recovery worker
    exec_page = wizard.execution_page
    exec_page.initializePage()
    worker = exec_page.worker
    assert worker is not None
    assert worker.mode == "RECOVERY"
    worker.wait(15000)
    qapp.processEvents()

    res = exec_page.execution_results
    assert res is not None
    assert res["mode"] == "RECOVERY"
    assert res["verification_result"] == "PASS"
    assert res["recovery_verdict"] == "FILES_RECOVERED"
    assert res["successfully_recovered"] >= 1
    assert len(res["recovered_files"]) >= 1

    # Initialize ResultsPage and verify table & buttons
    res_page = wizard.results_page
    res_page.initializePage()
    assert "FILE(S) RECOVERED" in res_page.verdict_label.text()
    assert res_page.files_table.rowCount() == len(res["recovered_files"])
    assert res_page.open_folder_btn.isHidden() is False
    assert res_page.summary_banner.isHidden() is False


def test_gui_recovery_zero_files_verdict(qapp, tmp_path):
    # Verify that scanning an empty / zeroed target does NOT display a false PASS for file recovery
    blank_file = tmp_path / "blank.raw"
    blank_file.write_bytes(b"\x00" * (1024 * 64))

    worker = ExecutionWorker(
        mode="RECOVERY",
        device_serial="BLANK-TEST-001",
        device_capacity=65536,
        policy_or_format="Aho-Corasick Carving",
        operator="TestOperator",
        target_path=str(blank_file),
        output_directory=str(tmp_path / "out_empty"),
    )
    results = []
    worker.finished_success.connect(lambda r: results.append(r))
    worker.start()
    worker.wait(5000)
    qapp.processEvents()

    assert len(results) == 1
    res = results[0]
    assert res["recovery_verdict"] == "NO_FILES_FOUND"
    assert res["successfully_recovered"] == 0
    assert len(res["recovered_files"]) == 0

    wizard = SanctumWizard()
    wizard.execution_page.execution_results = res
    wizard.results_page.initializePage()
    assert "NO VALID FILES RECOVERED" in wizard.results_page.verdict_label.text()
