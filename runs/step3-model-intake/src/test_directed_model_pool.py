import unittest

from directed_model_pool import classify_proposals, directed_prompt
from pool_admission import code_change


class DirectedModelPoolTest(unittest.TestCase):
    def test_prompt_keeps_independent_scoring_outside_model(self):
        messages = directed_prompt({"skeletons": {"before": "int sample(void) {}", "after": "int sample(void) {}"}})
        self.assertIn("完整 C 翻译单元", messages[0]["content"])
        self.assertNotIn("H_check", str(messages))
        self.assertIn("不要写推断出的事实或预测", messages[1]["content"])

    def test_classification_counts_real_admission_and_hard_pairs(self):
        proposals = [
            {"id": "a", "status": "admitted", "semantic_sha256": "one", "predictions": {
                "H_check": "quiet", "H_path": "report", "H_loop": "report"}},
            {"id": "b", "status": "admitted", "semantic_sha256": "one", "predictions": {
                "H_check": "quiet", "H_path": "report", "H_loop": "report"}},
            {"id": "c", "status": "unsupported_shape"},
        ]
        counts = classify_proposals(proposals)
        self.assertEqual(counts["raw"], 3)
        self.assertEqual(counts["admitted"], 2)
        self.assertEqual(counts["unique_admitted"], 1)
        self.assertEqual(counts["hard_divergent"], 2)
        self.assertEqual(counts["unique_hard_divergent"], 1)

    def test_goto_return_rewrite_is_a_single_control_factor(self):
        before = "int f(void) {\n if(bv.bv_val == NULL) break;\n for(i = 0; bvals[i].bv_val != NULL; i++) {}\n return 0;\n}"
        after = before.replace(" for(i = 0;", " if(bvals == NULL) goto done;\n for(i = 0;")
        after = after.replace(" return 0;", " done: return 0;")
        self.assertTrue(code_change(before, after, 'path_block_scope')['single_factor'])
        after = before.replace(" for(i = 0;", " if(bvals == NULL) goto done;\n for(i = 0;")
        after = after.replace(" return 0;", " done:\n return 0;")
        self.assertTrue(code_change(before, after, 'path_block_scope')['single_factor'])


if __name__ == "__main__":
    unittest.main()
