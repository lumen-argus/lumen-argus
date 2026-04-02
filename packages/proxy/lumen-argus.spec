# PyInstaller spec for lumen-argus proxy sidecar binary.
#
# Produces a single-file executable for Tauri sidecar.
# Includes dashboard static assets, community rules, and all dependencies.
#
# Build:
#   pyinstaller packages/proxy/lumen-argus.spec --distpath dist --workpath build
#
# Output: dist/lumen-argus
#
# For tray app, rename to arch-specific name:
#   cp dist/lumen-argus src-tauri/binaries/lumen-argus-aarch64-apple-darwin

import os
import sys

sys.path.insert(0, os.path.join(SPECPATH, '..', 'core'))

a = Analysis(
    [os.path.join(SPECPATH, 'lumen_argus', '__main__.py')],
    pathex=[
        os.path.join(SPECPATH, '..', 'core'),
    ],
    binaries=[],
    datas=[
        (os.path.join(SPECPATH, 'lumen_argus', 'dashboard', 'static'), 'lumen_argus/dashboard/static'),
        (os.path.join(SPECPATH, 'lumen_argus', 'rules', 'community.json'), 'lumen_argus/rules'),
    ],
    hiddenimports=[
        'lumen_argus_core',
        'lumen_argus_core.clients',
        'lumen_argus_core.detect',
        'lumen_argus_core.setup_wizard',
        'lumen_argus_core.watch',
        'lumen_argus_core.time_utils',
        'lumen_argus_core.enrollment',
        'lumen_argus_core.telemetry',
        'aiohttp',
        'aiohttp.web',
        'aiohttp.web_app',
        'aiohttp.web_runner',
        'aiohttp.connector',
        'aiohttp.client',
        'aiohttp.client_ws',
        'multidict',
        'yarl',
        'aiosignal',
        'frozenlist',
        'async_timeout',
        'ahocorasick',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'PIL',
        'doctest',
        'pydoc',
        'unittest',
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='lumen-argus',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=False,
    console=True,
    codesign_identity=os.environ.get('CODESIGN_IDENTITY', ''),
    entitlements_file=os.environ.get('ENTITLEMENTS_FILE', ''),
)
