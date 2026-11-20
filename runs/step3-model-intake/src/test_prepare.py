import unittest
from pathlib import Path
from prepare_model import prepare

ROOT=Path(__file__).resolve().parents[3]

class PromptBoundary(unittest.TestCase):
    def test_accepted_seed_export_has_only_reviewed_inputs(self):
        package=prepare(ROOT)
        self.assertEqual(package['seed_run'],'curl-openldap-2018-seed-v4')
        self.assertEqual(package['baseline'],'spec.openldap.H_check@1')
        self.assertEqual(len(package['models']),3)
        self.assertIn('bvals[i].bv_val',package['skeletons']['before'])
        self.assertIn('bvals[i].bv_val',package['skeletons']['after'])
        self.assertNotIn('verdict',str(package).lower())
        self.assertNotIn('api_key',str(package).lower())
        self.assertNotIn('reserve',str(package).lower())

if __name__=='__main__': unittest.main()
