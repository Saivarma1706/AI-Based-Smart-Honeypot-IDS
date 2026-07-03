# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_submodules

# Project paths
PROJECT_ROOT = r"C:\AI-Based-Smart-Honeypot-IDS\Smart_Honeypot_IDS"
APP_DIR = os.path.join(PROJECT_ROOT, "app")

# Hidden imports
app_hidden = collect_submodules("app")

third_party_hidden = [
    "flask_wtf.csrf",
    "wtforms.csrf.session",
    "sklearn.ensemble._forest",
    "sklearn.tree._tree",
    "sklearn.neighbors._typedefs",
    "sklearn.utils._weight_vector",
    "joblib.externals.cloudpickle",
    "reportlab.pdfbase._fontdata",
    "reportlab.pdfbase._metrics",
    "numpy.core._methods",
]

stdlib_hidden = [
    "unittest",
    "unittest.mock",
]

hiddenimports = app_hidden + third_party_hidden + stdlib_hidden

# Data files
datas = [
    (os.path.join(PROJECT_ROOT, "templates"), "templates"),
    (os.path.join(PROJECT_ROOT, "static"), "static"),
    (os.path.join(PROJECT_ROOT, "models"), "models"),
]

# Exclusions
excludes = [
    "tkinter",
    "matplotlib",
    "pytest",
    "IPython",
    "notebook",
    "PyQt5",
    "PySide2",
    "wx",
    "gtk",
    "test",
    "setuptools",
    "scipy.spatial.cKDTree",
]

a = Analysis(
    [os.path.join(APP_DIR, "main.py")],
    pathex=[PROJECT_ROOT, APP_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SmartHoneypotIDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="SmartHoneypotIDS",
)