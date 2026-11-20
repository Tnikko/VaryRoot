import json
import unittest
from pathlib import Path
from pool_admission import code_change, make_case_facts, predictions, freeze_pools
from admission import analyze_batch, derive_facts

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'runs/step3-model-intake/out'

class PoolAdmissionTest(unittest.TestCase):
    def test_ast_facts_and_real_interpreter_separate_hypotheses(self):
        payload=json.loads((OUT/'proposal-input.json').read_text())
        before=payload['skeletons']['before']
        code=before.replace('    for(i = 0; bvals[i].bv_val != NULL; i++) {',
                            '    if(bvals == NULL) break;\n    for(i = 0; bvals[i].bv_val != NULL; i++) {')
        ast=analyze_batch(ROOT,{'exit':code},'prediction-test')['exit']
        facts=derive_facts(ast)
        cases=make_case_facts(ROOT,'exit',facts)
        got=predictions(payload,cases)
        self.assertEqual(got['spec.openldap.H_check@1'],'quiet')
        self.assertEqual(got['spec.openldap.H_path@1'],'quiet')
        self.assertEqual(got['spec.openldap.H_loop@1'],'uncovered')
        self.assertEqual(cases['facts'][0]['target_ref'],cases['target']['id']+'@1')

    def test_single_line_alias_and_wrong_object_are_not_confounded(self):
        payload=json.loads((OUT/'proposal-input.json').read_text())
        r2=json.loads((OUT/'model-02.response.json').read_text())
        proposals=json.loads(r2['choices'][0]['message']['content'])['proposals']
        self.assertTrue(code_change(payload['skeletons']['before'],proposals[4]['source'],'propagation')['single_factor'])
        r3=json.loads((OUT/'model-03.response.json').read_text())
        wrong=json.loads(r3['choices'][0]['message']['content'])['proposals'][5]
        self.assertTrue(code_change(payload['skeletons']['before'],wrong['source'],'invalid_source')['single_factor'])

    def test_frozen_three_calls_have_ast_trace_and_no_overlap(self):
        admission=json.loads((OUT/'admission.json').read_text())
        trace=json.loads((OUT/'derivations.json').read_text())
        model=[r for r in admission['rows'] if r['pool'].startswith('model-')]
        self.assertEqual(len(model),17)
        self.assertEqual(len(admission['frozen']),4)
        identities=[]
        for pool in ('model-01','model-02','model-03'):
            for case_id in admission['frozen'][pool]:
                row=next(r for r in model if r['id']==case_id)
                self.assertEqual(row['ast_sha256'],trace[case_id]['ast']['ast_sha256'])
                self.assertIn(row['class'],('admitted_divergent','admitted_no_new_divergence'))
                identities.append(row['semantic_sha256'])
        self.assertEqual(len(identities),len(set(identities)))
        self.assertEqual(sum(r['divergence']['hard'] for r in model if 'divergence' in r),0)
        self.assertEqual(sum(r['divergence']['coverage'] for r in model if 'divergence' in r),3)

    def test_single_factor_and_duplicate_freeze(self):
        before='x = 1;\nif (p) use(p);\n'
        good='x = 1;\nif (p) use(p);\nif (!p) return;\n'
        bad='x = 2;\nif (p) use(p);\nif (!p) return;\n'
        self.assertTrue(code_change(before,good,'path_block_scope')['single_factor'])
        self.assertFalse(code_change(before,bad,'path_block_scope')['single_factor'])
        rows=[
          {'pool':'p1','id':'a','class':'admitted_divergent','source_sha256':'h1','semantic_sha256':'s1'},
          {'pool':'p2','id':'b','class':'admitted_divergent','source_sha256':'h1','semantic_sha256':'s1'},
          {'pool':'p2','id':'c','class':'admitted_no_new_divergence','source_sha256':'h2','semantic_sha256':'s2'}]
        frozen=freeze_pools(rows)
        self.assertEqual(frozen['p1'],['a'])
        self.assertEqual(frozen['p2'],['c'])
        self.assertEqual(rows[1]['class'],'admitted_no_new_divergence')
        self.assertEqual(rows[1]['reason'],'cross_pool_duplicate')

if __name__=='__main__': unittest.main()
