import os
from setuptools import setup, Extension

build_native = os.environ.get("SANCTUM_BUILD_NATIVE", "0") == "1"

if build_native:
    native_module = Extension(
        "sanctum_native",
        sources=["ext/sanctum_native.c"],
    )
    setup(ext_modules=[native_module])
else:
    setup()
