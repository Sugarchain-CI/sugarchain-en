#!/usr/bin/env python3
"""Separate verbose diagnostic; never count its timing as a scored run."""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("native_sync", Path(__file__).with_name("native-sync.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
original = bench.subprocess.Popen


def verbose_popen(command, *args, **kwargs):
    return original([*command, "-debug=net", "-debug=validation", "-logtimemicros=1", "-logthreadnames=1"], *args, **kwargs)


bench.subprocess.Popen = verbose_popen
bench.main()
