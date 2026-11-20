"""Record Agent C's actual admission result for OpenLDAP B6 handoffs."""
import json
from pathlib import Path

from varyroot.agent_c import compile_manifest

ROOT = Path('/home/tq/varyroot/runs/step4-paired/out/clean-vm')
summary = {}
for pool in ('model01', 'model02', 'model03', 'offline'):
    for group in ('random', 'divergence'):
        key = pool + '.' + group
        source = ROOT / 'handoffs' / pool / group
        try:
            result = compile_manifest(source)
        except (ValueError, KeyError, TypeError) as exc:
            summary[key] = {'admitted': False, 'error_type': type(exc).__name__,
                            'reason': str(exc), 'freeze_issued': False}
        else:
            summary[key] = {'admitted': True, 'family': result['family'],
                            'freeze_issued': False}
path = ROOT / 'c-capability.json'
path.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
print(json.dumps(summary, sort_keys=True))
