import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'scripts' / 'audit_main_protection.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

SHA = 'a' * 40
CONTEXTS = ('verify', 'actual-broker', 'local-repro', 'contracts', 'evidence')


def valid():
    return ({'name':'main', 'protected':True, 'commit':{'sha':SHA}}, [
        {'type':'pull_request'}, {'type':'non_fast_forward'}, {'type':'deletion'},
        {'type':'required_status_checks', 'parameters':{'strict_required_status_checks_policy':True, 'required_status_checks':[{'context':x} for x in CONTEXTS]}},
    ])


class AuditTests(unittest.TestCase):
    def test_positive_is_only_a_configuration_observation(self):
        branch, rules = valid()
        self.assertEqual(audit.evaluate(branch, rules, SHA, CONTEXTS), [])

    def test_no_protection_or_empty_rules_fail_closed(self):
        branch, rules = valid()
        branch['protected'] = False
        self.assertTrue(audit.evaluate(branch, rules, SHA, CONTEXTS))
        branch['protected'] = True
        self.assertTrue(audit.evaluate(branch, [], SHA, CONTEXTS))
        self.assertTrue(audit.evaluate(branch, None, SHA, CONTEXTS))

    def test_requires_pr_nonfastforward_deletion_and_exact_contexts(self):
        branch, rules = valid()
        for absent in ('pull_request','non_fast_forward','deletion'):
            with self.subTest(absent=absent):
                self.assertTrue(audit.evaluate(branch,[r for r in rules if r['type'] != absent],SHA,CONTEXTS))
        rules[-1]['parameters']['required_status_checks'] = [{'context':'verify'}]
        self.assertTrue(any('required job contexts' in s for s in audit.evaluate(branch,rules,SHA,CONTEXTS)))

    def test_missing_incomplete_duplicate_or_non_strict_rule(self):
        branch,rules=valid()
        rules[-1]['parameters']['strict_required_status_checks_policy']=False
        self.assertTrue(audit.evaluate(branch,rules,SHA,CONTEXTS))
        rules[-1]['parameters']['strict_required_status_checks_policy']=True
        rules[-1]['parameters']['required_status_checks'].append({'context':'verify'})
        self.assertTrue(audit.evaluate(branch,rules,SHA,CONTEXTS))
        rules[-1]['parameters']['required_status_checks'] = [{'context':x} for x in CONTEXTS]
        rules.append({'type':'required_status_checks', 'parameters':{}})
        self.assertTrue(audit.evaluate(branch,rules,SHA,CONTEXTS))

    def test_stale_or_untyped_facts_never_pass(self):
        branch,rules=valid()
        self.assertTrue(audit.evaluate(branch,rules,'b'*40,CONTEXTS))
        self.assertTrue(audit.evaluate({'name':'main','protected':1,'commit':{'sha':SHA}},rules,SHA,CONTEXTS))
        self.assertTrue(audit.evaluate(branch,{'rules':rules},SHA,CONTEXTS))
        self.assertTrue(audit.evaluate({},rules,SHA,CONTEXTS))


if __name__ == '__main__':
    unittest.main()
