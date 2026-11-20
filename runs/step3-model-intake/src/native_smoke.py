import ctypes
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from tools.frontend.build import COMPILER, LOCK, fingerprint
from tools.verifier.build import compile_probes

lock=json.loads(LOCK.read_bytes())
assert fingerprint(COMPILER.resolve()) == lock['files']['bin/clang']
with TemporaryDirectory() as tmp:
    result=compile_probes(Path(tmp))
    assert 'npd_before' in result and 'oob_before' in result
    lib=ctypes.CDLL(str(Path(tmp)/'edge_c.so'))
    assert lib is not None
print('locked_native_build=ok')
