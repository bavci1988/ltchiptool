# -*- mode: python ; coding: utf-8 -*-

from pkgutil import iter_modules

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import ltctplugin

hiddenimports = [
    name
    for _, name, _ in iter_modules(ltctplugin.__path__, ltctplugin.__name__ + ".")
    if name != "ltctplugin.base"
]

# commands are loaded by name at run time, so PyInstaller does not see them
hiddenimports += collect_submodules("ltchiptool.commands")
hiddenimports += collect_submodules("ltchiptool.soc")
hiddenimports += collect_submodules("uf2tool")

datas = []

for module in hiddenimports:
    datas += collect_data_files(module)

a = Analysis(
    ["cli.py"],
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
    name="ltchiptool-cli",
    strip=False,
    upx=True,
    console=True,
    icon=["ltchiptool\\gui\\ltchiptool.ico"],
    version="gui-win32.txt",
)
