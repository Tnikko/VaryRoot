import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import ast_semantic_sha256, clang_ast, clang_token_sha256
from varyroot.b_static_retry import source_sha256


class HistoricalExclusionsTest(unittest.TestCase):
    def test_semantic_table_covers_every_v3_preexisting_source(self):
        root = Path(__file__).resolve().parents[1]
        old = json.loads((root / 'data/prereg-blind-v3/historical-exclusions.json').read_bytes())
        new = json.loads((root / 'data/exclusions-semantic-v1/historical-exclusions.json').read_bytes())
        self.assertEqual(new['sources'], {'input_entries': 49, 'resolved': 49, 'ast_available': 44})
        self.assertEqual([row['source_sha256'] for row in new['entries']],
                         [row['source_sha256'] for row in old['entries']])
        self.assertTrue(all(len(row['token_sha256']) == 64 for row in new['entries']))
        self.assertEqual(sum(row['ast_sha256'] is not None for row in new['entries']), 44)

    @unittest.skipUnless(shutil.which('clang-18') and
                         (Path(os.environ.get('VARYROOT_RUNS', '/home/tq/varyroot/runs')) /
                          'blind-pool-v3-2026-11-21/openldap/generation-result.json').exists(),
                         'v3 archive and Clang 18 unavailable')
    def test_v3_openldap_spacing_variants_match_semantic_history(self):
        runs = Path(os.environ.get('VARYROOT_RUNS', '/home/tq/varyroot/runs'))
        rows = json.loads((runs / 'blind-pool-v3-2026-11-21/openldap/generation-result.json').read_bytes())['rows']
        table = json.loads((Path(__file__).resolve().parents[1] /
                            'data/exclusions-semantic-v1/historical-exclusions.json').read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            headers = runs / 'blind-pool-v3-2026-11-21/openldap/compile-headers'
            for index in (0, 7, 8):
                with self.subTest(index=index):
                    row = rows[index]
                    path = Path(folder) / f'candidate-{index}.c'
                    path.write_text(row['source'])
                    argv = ['clang-18', '--no-default-config', '--target=x86_64-pc-linux-gnu',
                            '-x', 'c', '-std=gnu17', '-I' + str(headers / 'ldap/include'),
                            '-isystem', str(headers / 'sys/usr/include/x86_64-linux-gnu'),
                            '-isystem', str(headers / 'sys/usr/include'), '-c', str(path),
                            '-o', str(path) + '.o']
                    ast, status = clang_ast(argv, folder, 'ldap_recv_slice')
                    self.assertEqual(status['exit_code'], 0, status)
                    token, shape = clang_token_sha256(row['source']), ast_semantic_sha256(ast)
                    self.assertTrue(any(token == entry['token_sha256'] or
                                        shape == entry['ast_sha256'] for entry in table['entries']))
                    if index in (0, 7):
                        self.assertNotIn(source_sha256(row['source']),
                                         {entry['source_sha256'] for entry in table['entries']})

    def test_locked_observed_sources_are_unique_and_provenanced(self):
        path = Path(__file__).resolve().parents[1] / "data/prereg-blind-v1/historical-exclusions.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data["entries"]
        hashes = [row["source_sha256"] for row in entries]
        self.assertEqual(hashes, sorted(set(hashes)))
        self.assertEqual(len(entries), data["sources"]["unique_source_hashes"])
        self.assertEqual(data["sources"]["step4d_raw_model_responses"], 3)
        self.assertEqual(sum(len(row["origins"]) for row in entries),
                         data["sources"]["observed_source_rows"])
        self.assertTrue(any(any(origin.startswith("step4f:source/parent/") for origin in row["origins"])
                            for row in entries))
        self.assertTrue(any(any(origin.startswith("step4d:model-03.response.json") for origin in row["origins"])
                            for row in entries))


if __name__ == "__main__":
    unittest.main()
