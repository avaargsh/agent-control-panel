from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'scripts' / 'audit_main_protection.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

SHA = 'a' * 40
CONTEXTS = ('verify', 'actual-broker', 'local-repro', 'contracts', 'evidence')


def valid():
    return ({'name':'main', 'protected':True, 'commit':{'sha':SHA}}, [
        {'type':'pull_request', 'parameters':{'required_review_thread_resolution':True}}, {'type':'non_fast_forward'}, {'type':'deletion'},
        {'type':'required_status_checks', 'parameters':{'strict_required_status_checks_policy':True, 'required_status_checks':[{'context':x} for x in CONTEXTS]}},
    ])


class AuditTests(unittest.TestCase):
    def test_defaults_are_only_unconditional_pr_job_contexts(self):
        self.assertEqual(audit.DEFAULT_CONTEXTS, ('verify', 'contracts', 'evidence'))
        self.assertNotIn('actual-broker', audit.DEFAULT_CONTEXTS)
        self.assertNotIn('local-repro', audit.DEFAULT_CONTEXTS)

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

    def test_unresolved_review_threads_must_block_even_if_other_rules_match(self):
        branch, rules = valid()
        rules[0]['parameters'] = {'required_review_thread_resolution': False}
        self.assertTrue(any('conversation' in e or 'review thread' in e
                            for e in audit.evaluate(branch, rules, SHA, audit.DEFAULT_CONTEXTS)))
        rules[0]['parameters'] = {}
        self.assertTrue(audit.evaluate(branch, rules, SHA, audit.DEFAULT_CONTEXTS))
        rules[0]['parameters'] = {'required_review_thread_resolution': True}
        self.assertEqual(audit.evaluate(branch, rules, SHA, audit.DEFAULT_CONTEXTS), [])

    def test_effective_rules_are_paginated_without_trusting_partial_first_page(self):
        branch, valid_rules = valid()
        calls = []
        filler = [{'type': 'commit_message_pattern'} for _ in range(96)]
        first_page = filler + valid_rules  # 100 items; the next page could conflict
        def fake_fetch(repo, path, token):
            calls.append(path)
            if path.endswith('page=1'):
                return first_page
            if path.endswith('page=2'):
                return [{'type': 'required_status_checks', 'parameters': {}}]
            raise AssertionError('unexpected page request')
        all_rules = audit.fetch_all_effective_rules('avaargsh/agent-control-panel', 'token', getter=fake_fetch)
        self.assertEqual(len(all_rules), 101)
        self.assertEqual(len(calls), 2)
        self.assertTrue(audit.evaluate(branch, all_rules, SHA, audit.DEFAULT_CONTEXTS))

    def test_rule_pagination_fails_closed_for_malformed_or_unbounded_pages(self):
        for result in ({'rules': []}, 'not a list', None):
            with self.subTest(result=result):
                with self.assertRaises(ValueError):
                    audit.fetch_all_effective_rules('avaargsh/agent-control-panel', 'token',
                                                    getter=lambda *_: result)
        with self.assertRaises(ValueError):
            audit.fetch_all_effective_rules('avaargsh/agent-control-panel', 'token',
                                            getter=lambda *_: [{'type': 'pull_request'}] * 100,
                                            max_pages=2)

    def test_main_is_rechecked_after_reading_effective_rules(self):
        branch, rules = valid()
        for final_branch in (branch, {**branch, 'commit': {'sha': 'b' * 40}},
                             {**branch, 'protected': False}, {}):
            with self.subTest(final_branch=final_branch):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.dict('os.environ', {'ACP_GOVERNANCE_READ_TOKEN': 'test-token'}), \
                        patch.object(audit, 'fetch', side_effect=[branch, rules, final_branch]) as fetch, \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    code = audit.main(['--repository', 'avaargsh/agent-control-panel',
                                       '--expected-main', SHA])
                self.assertEqual(code, 0 if final_branch == branch else 1)
                self.assertEqual([call.args[1] for call in fetch.call_args_list],
                                 ['/branches/main', '/rules/branches/main?per_page=100&page=1',
                                  '/branches/main'])
                if final_branch != branch:
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertIn('MAIN_PROTECTION_AUDIT=BLOCKED', stderr.getvalue())

    def test_stale_or_untyped_facts_never_pass(self):
        branch,rules=valid()
        self.assertTrue(audit.evaluate(branch,rules,'b'*40,CONTEXTS))
        self.assertTrue(audit.evaluate({'name':'main','protected':1,'commit':{'sha':SHA}},rules,SHA,CONTEXTS))
        self.assertTrue(audit.evaluate(branch,{'rules':rules},SHA,CONTEXTS))
        self.assertTrue(audit.evaluate({},rules,SHA,CONTEXTS))


if __name__ == '__main__':
    unittest.main()
