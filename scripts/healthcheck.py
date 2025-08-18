#!/usr/bin/env python3
import sys
from importlib import import_module

mods = [
    "numpy","pandas","sklearn","scipy","PIL","playwright.sync_api",
]
print("python:", sys.version.split()[0])
for m in mods:
    try:
        import_module(m)
        print("OK:", m)
    except Exception as e:
        print("FAIL:", m, "->", type(e).__name__, e)
