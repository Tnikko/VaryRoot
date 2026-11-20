#!/bin/bash
cd /dev_sdb/tq/VaryRoot
P=toolchains/cpython-3.13.2-linux-x86_64-gnu/bin/python3.13
"$P" runs/interface3d-production/src/toolchain_runner.py python -m unittest discover -s tests -p 'test_*.py' -v > runs/interface3d-production/out/launcher-tests.log 2>&1
code=$?
printf '%s\n' "$code" > runs/interface3d-production/out/launcher-tests.exit
exit "$code"
