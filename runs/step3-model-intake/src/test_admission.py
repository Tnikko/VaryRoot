import json
import unittest
from pathlib import Path
from admission import analyze_batch, derive_facts

ROOT=Path(__file__).resolve().parents[3]

class AstAdmission(unittest.TestCase):
    def test_locked_clang_distinguishes_exit_from_surface_check(self):
        raw=json.loads((ROOT/'runs/step3-model-intake/out/proposal-input.json').read_text())['skeletons']
        before=raw['before']
        inserted=before.replace('    for(i = 0; bvals[i].bv_val != NULL; i++) {',
                                 '    if(bvals == NULL) break;\n    for(i = 0; bvals[i].bv_val != NULL; i++) {')
        checked=before.replace('    for(i = 0; bvals[i].bv_val != NULL; i++) {',
                                '    if(bvals == NULL) { }\n    for(i = 0; bvals[i].bv_val != NULL; i++) {')
        rows=analyze_batch(ROOT,{'before':before,'after':raw['after'],'exit':inserted,'check':checked},'test')
        self.assertEqual(set(r['status'] for r in rows.values()),{'valid'})
        self.assertEqual(derive_facts(rows['before'])['blocked'],False)
        self.assertEqual(derive_facts(rows['after'])['loop_direct'],True)
        self.assertEqual(derive_facts(rows['exit'])['blocked'],True)
        self.assertEqual(derive_facts(rows['exit'])['loop_direct'],False)
        self.assertEqual(derive_facts(rows['check'])['check_seen'],True)
        self.assertEqual(derive_facts(rows['check'])['blocked'],False)

if __name__=='__main__': unittest.main()
