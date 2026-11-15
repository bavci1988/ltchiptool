# -*- mode: python ; coding: utf-8 -*-

from pkgutil import iter_modules

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

import ltctplugin

hiddenimports = [
    name
    for _, name, _ in iter_modules(ltctplugin.__path__, ltctplugin.__name__ + ".")
    if name != "ltctplugin.base"
]

datas = []

for module in hiddenimports:
    datas += collect_data_files(module)

# packages that read their own version at import time (inquirer, used by upk2esphome)
for package in ("readchar", "inquirer"):
    try:
        datas += copy_metadata(package)
    except Exception:
        pass

a = Analysis(
    ["gui.py"],
    datas=[
        ("ltchiptool.txt", "."),
        ("ltchiptool/boards/", "./boards/"),
        ("ltchiptool/platform.json", "."),
        ("ltchiptool/families.json", "."),
        ("ltchiptool/gui/ltchiptool-192x192.png", "."),
        ("ltchiptool/gui/ltchiptool.ico", "."),
        ("ltchiptool/gui/ltchiptool.xrc", "."),
        ("ltchiptool/gui/ko-fi.png", "."),
        ("ltchiptool/gui/colors.json", "."),
        ("pyproject.toml", "."),
        ("ltchiptool/soc/xr806/util/brom_stub.bin", "ltchiptool/soc/xr806/util/"),
    ]
    + datas,
    hiddenimports=hiddenimports,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="ltchiptool",
    strip=False,
    upx=True,
    console=False,
    icon=["ltchiptool\\gui\\ltchiptool.ico"],
    version="gui-win32.txt",
)
