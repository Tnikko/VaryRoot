#!/bin/bash
cd /dev_sdb/tq/VaryRoot
export PYTHONPATH=$PWD VARYROOT_ROLE_BACKEND=namespace VARYROOT_NAMESPACE_LOCK=$PWD/toolchains/namespace-v1/image-lock.json TMPDIR=$PWD/.tmp
P=toolchains/cpython-3.13.2-linux-x86_64-gnu/bin/python3.13
"$P" -m unittest discover -s tests -p 'test_*.py' -v > runs/interface3d-production/out/full-tests.log 2>&1
code=$?
printf '%s\n' "$code" > runs/interface3d-production/out/full-tests.exit
exit "$code"
