
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all

# Coletar dependências completas
flask_datas, flask_binaries, flask_hidden = collect_all('flask')
werkzeug_datas, werkzeug_binaries, werkzeug_hidden = collect_all('werkzeug')
flet_datas, flet_binaries, flet_hidden = collect_all('flet')
qrcode_datas, qrcode_binaries, qrcode_hidden = collect_all('qrcode')
pillow_datas, pillow_binaries, pillow_hidden = collect_all('PIL')

a = Analysis(
    ['app_desktop.py'],

    pathex=[],

    binaries=[
        *flask_binaries,
        *werkzeug_binaries,
        *flet_binaries,
        *qrcode_binaries,
        *pillow_binaries,
    ],

    datas=[
        *flask_datas,
        *werkzeug_datas,
        *flet_datas,
        *qrcode_datas,
        *pillow_datas,
    ],

    hiddenimports=[
        'flask',
        'werkzeug',
        'jinja2',
        'click',
        'itsdangerous',
        'markupsafe',
        'qrcode',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'socket',
        'threading',
        'flet',
        'flet.core',
        'flet.controls',
        *flask_hidden,
        *werkzeug_hidden,
        *flet_hidden,
        *qrcode_hidden,
        *pillow_hidden,
    ],

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],

    excludes=[
        'PyQt5',
        'PyQt6',
        'matplotlib',
        'pandas',
        'numpy'
    ],

    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],

    name='NexusDrop',

    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,

    console=False,

    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
