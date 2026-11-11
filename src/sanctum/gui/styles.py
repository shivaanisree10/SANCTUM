"""
Professional Dark Navy Modern Stylesheet for SANCTUM GUI.
Tailored for academic presentations, forensic laboratory reviews, and defense demonstrations.
Palette:
- Background: #0F172A (Deep Slate Navy), #1E293B (Card/Panel Slate)
- Borders: #334155 (Subtle border), #475569 (Focused border)
- Text: #F8FAFC (Primary white), #94A3B8 (Muted silver/gray), #CBD5E1 (Secondary)
- Primary / Accent: #2563EB / #3B82F6 (Vibrant Blue)
- Success: #10B981 / #059669 (Emerald Green)
- Warning / Danger: #EF4444 / #DC2626 (Vibrant Red)
"""

ACCESSIBLE_STYLESHEET = """
QWidget {
    background-color: #0F172A;
    color: #F8FAFC;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

/* Keyboard focus indicator */
QWidget:focus {
    outline: 2px solid #3B82F6;
}

QWizard {
    background-color: #0F172A;
}

QLabel {
    color: #F8FAFC;
}

QLabel#titleLabel {
    font-size: 17px;
    font-weight: 700;
    color: #60A5FA;
    margin-bottom: 4px;
}

QLabel#subtitleLabel {
    font-size: 12px;
    color: #94A3B8;
    margin-bottom: 8px;
}

QLabel#optionDescription {
    color: #94A3B8;
    font-size: 12px;
    margin-left: 28px;
    margin-bottom: 8px;
}

QLabel#warningLabel {
    font-size: 13px;
    font-weight: bold;
    color: #EF4444;
    background-color: rgba(239, 68, 68, 0.12);
    border: 1px solid #DC2626;
    border-radius: 6px;
    padding: 10px;
}

QLabel#successVerdict {
    font-size: 16px;
    font-weight: bold;
    color: #34D399;
    background-color: rgba(16, 185, 129, 0.12);
    border: 1px solid #10B981;
    border-radius: 6px;
    padding: 10px;
}

QLabel#neutralVerdict {
    font-size: 16px;
    font-weight: bold;
    color: #60A5FA;
    background-color: rgba(59, 130, 246, 0.12);
    border: 1px solid #3B82F6;
    border-radius: 6px;
    padding: 10px;
}

QRadioButton, QCheckBox {
    spacing: 8px;
    font-size: 13px;
    font-weight: 600;
    color: #F8FAFC;
    padding: 4px;
}

QRadioButton::indicator, QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #64748B;
    border-radius: 4px;
    background: #1E293B;
}

QRadioButton::indicator {
    border-radius: 10px;
}

QRadioButton::indicator:checked {
    background-color: #3B82F6;
    border: 2px solid #60A5FA;
}

QRadioButton#destructiveRadio::indicator:checked {
    background-color: #EF4444;
    border: 2px solid #F87171;
}

QCheckBox::indicator:checked {
    background-color: #3B82F6;
    border: 2px solid #60A5FA;
}

QPushButton {
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 16px;
    font-weight: 600;
    min-height: 26px;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #64748B;
}

QPushButton:pressed {
    background-color: #0F172A;
}

QPushButton:disabled {
    background-color: #1E293B;
    color: #475569;
    border-color: #334155;
}

QPushButton#primaryButton {
    background-color: #2563EB;
    color: #FFFFFF;
    border: 1px solid #3B82F6;
}

QPushButton#primaryButton:hover {
    background-color: #1D4ED8;
}

QPushButton#primaryButton:pressed {
    background-color: #1E40AF;
}

QPushButton#toggleButton {
    background-color: #1E293B;
    color: #93C5FD;
    border: 1px solid #334155;
    text-align: left;
    padding: 6px 12px;
    font-weight: 600;
}

QPushButton#toggleButton:hover {
    background-color: #27354A;
    color: #BFDBFE;
}

QPushButton#destructiveButton {
    background-color: #991B1B;
    color: #FFFFFF;
    border: 1px solid #EF4444;
    font-weight: bold;
}

QPushButton#destructiveButton:hover {
    background-color: #DC2626;
}

QPushButton#destructiveButton:disabled {
    background-color: #1E293B;
    color: #475569;
    border-color: #334155;
}

QTableWidget {
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid #334155;
    gridline-color: #334155;
    selection-background-color: #2563EB;
    selection-color: #FFFFFF;
    border-radius: 4px;
}

QHeaderView::section {
    background-color: #0F172A;
    color: #CBD5E1;
    font-weight: 600;
    padding: 6px;
    border: 1px solid #334155;
}

QProgressBar {
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    font-weight: bold;
    color: #FFFFFF;
    background-color: #1E293B;
    height: 24px;
}

QProgressBar::chunk {
    background-color: #2563EB;
    border-radius: 5px;
}

QLineEdit, QTextEdit, QComboBox {
    background-color: #1E293B;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 10px;
    color: #F8FAFC;
}

QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #3B82F6;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QGroupBox {
    border: 1px solid #334155;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: 600;
    color: #94A3B8;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
}
"""
