import unittest

from tools.codeql07.probe_curl_pair import compare_alerts


class CurlProbeTests(unittest.TestCase):
    def test_exact_coordinates_define_common_and_lane_only_alerts(self):
        shared = {'filename': 'openldap.c', 'sl': 10, 'sc': 2, 'el': 10, 'ec': 16,
                  'multiplicity': 1, 'expression': 'bvals[i].bv_val'}
        other = dict(shared, sl=11, el=11)
        result = compare_alerts([shared], [shared, other])
        self.assertEqual(result['common'], [shared])
        self.assertEqual(result['only_Q0'], [])
        self.assertEqual(result['only_Qstar'], [other])


if __name__ == '__main__':
    unittest.main()
