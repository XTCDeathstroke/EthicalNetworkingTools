# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['ENWTS.py'],
    pathex=[],
    binaries=[],
    datas=[('README.md', '.'), ('LICENSE.txt', '.'), ('COPYRIGHT.txt', '.'), ('CHANGELOG.md', '.'), ('SECURITY.md', '.'), ('CONTRIBUTING.md', '.'), ('CONTRIBUTING.md', '.'), ('CODE_OF_CONDUCT.md', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ENWTS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['ENWTS_ICON.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ENWTS',
)
