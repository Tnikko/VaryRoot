import unittest

from varyroot.agent_c import emit_nullable_queries, load_nullable_contract


class NullableOutputFamilyTests(unittest.TestCase):
    def test_second_unrelated_api_uses_the_same_emitter(self):
        first = load_nullable_contract('openldap.reference.2.4.45@1')
        second = load_nullable_contract('test.reference.decoder@1')
        self.assertNotEqual(first['call']['name'], second['call']['name'])
        self.assertNotEqual(first['call']['output_argument'], second['call']['output_argument'])
        self.assertNotEqual(first['call']['success_value'], second['call']['success_value'])
        for contract in (first, second):
            result = emit_nullable_queries(dict(contract=contract,
                lanes={'Q0': {'guard': 'check_seen'}, 'Qstar': {'guard': 'blocked'}}))
            shared = result['nullable_output.qll'].decode()
            parameters = result['contract.qll'].decode()
            self.assertNotIn(contract['call']['name'], shared)
            self.assertNotIn(contract['call']['success_value'], shared)
            self.assertIn(contract['call']['name'], parameters)
            self.assertIn(str(contract['call']['output_argument']), parameters)
            self.assertIn(contract['call']['success_value'], parameters)
            self.assertNotEqual(result['Q0.ql'], result['Qstar.ql'])

    def test_three_guard_forms_are_emitted_from_ir(self):
        contract = load_nullable_contract('test.reference.decoder@1')
        result = emit_nullable_queries(dict(contract=contract,
            lanes={'Q0': {'guard': 'check_seen'}, 'Qstar': {'guard': 'blocked'}}))
        self.assertIn('checkSeen(e)', result['Q0.ql'].decode())
        self.assertIn('blocked(e)', result['Qstar.ql'].decode())
        loop = emit_nullable_queries(dict(contract=contract,
            lanes={'Q0': {'guard': 'loop_direct'}, 'Qstar': {'guard': 'blocked'}}))
        self.assertIn('loopDirect(e)', loop['Q0.ql'].decode())


if __name__ == '__main__':
    unittest.main()
