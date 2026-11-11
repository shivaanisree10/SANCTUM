# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['src/sanctum/cli/main.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('config/default_policies.yaml', 'config'),
        ('config/signatures.yaml', 'config'),
    ],
    hiddenimports=[
        'pydantic',
        'typer',
        'PyQt6',
        'fpdf',
        'qrcode',
        'yaml',
        'sqlite3',
        'zoneinfo',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='sanctum',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
