import sys
from PyQt6.QtWidgets import QApplication
from sanctum.gui.wizard import SanctumWizard


def run_gui() -> int:
    """Launch the Sanctum PyQt6 Graphical User Interface."""
    app = QApplication.instance() or QApplication(sys.argv)
    wizard = SanctumWizard()
    wizard.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run_gui())
