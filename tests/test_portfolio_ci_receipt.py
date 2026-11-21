"""Regression tests for a fail-closed exported GitHub Actions run receipt."""
import copy
import importlib.util
import json
import io
import contextlib
import tempfile
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'portfolio_ci_receipt.py'
spec = importlib.util.spec_from_file_location('portfolio_ci_receipt', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SHA = 'a' * 40
GOLDEN_STEP = 'Execute live OAuth to same Run Temporal recovery and Decision acceptance'

def fixture():
    return {
        'databaseId': 123456789,
        'url': 'https://github.com/avaargsh/agent-control-panel/actions/runs/123456789',
        'workflowName': 'Same ACP Run real Guard Plan Step mTLS (non-production)',
        'headSha': SHA,
        'headBranch': 'main',
        'event': 'workflow_dispatch',
        'status': 'completed',
        'conclusion': 'success',
        'attempt': 1,
        'jobs': [{
            'name': 'e2e', 'status': 'completed', 'conclusion': 'success',
            'steps': [{'name': GOLDEN_STEP, 'status':'completed','conclusion':'success'}],
        }],
    }

class ReceiptTest(unittest.TestCase):
    def test_exact_golden_pass_returns_bounded_observation(self):
        receipt = module.verify_run(fixture(), SHA, 'golden')
        self.assertEqual(receipt['run_id'], 123456789)
        self.assertEqual(receipt['head_sha'], SHA)
        self.assertEqual(receipt['grade'], 'CI_METADATA_CHECK_ONLY')
        self.assertFalse(receipt['production_accepted'])
        self.assertEqual(receipt['required_job'], 'e2e')

    def test_golden_contract_matches_actual_github_workflow(self):
        workflow = (SCRIPT.parent.parent / '.github' / 'workflows' / 'acp-temporal-golden-path.yml').read_text(encoding='utf-8')
        self.assertTrue(workflow.startswith('name: '))
        self.assertEqual(module.SCENARIOS['golden'][0], workflow.splitlines()[0].removeprefix('name: '))
        self.assertIn('  e2e:', workflow)
        self.assertIn('      - name: ' + GOLDEN_STEP, workflow)

    def test_stale_golden_workflow_name_is_denied(self):
        data = fixture()
        data['workflowName'] = 'Same ACP Run to recovered Decision acceptance (non-production)'
        with self.assertRaises(module.ReceiptError):
            module.verify_run(data, SHA, 'golden')

    def test_wrong_sha_is_denied(self):
        with self.assertRaises(module.ReceiptError):
            module.verify_run(fixture(), 'b'*40, 'golden')

    def test_wrong_workflow_is_denied(self):
        data = fixture(); data['workflowName'] = 'Another job'
        with self.assertRaises(module.ReceiptError):
            module.verify_run(data, SHA, 'golden')

    def test_completed_but_failed_or_skipped_step_is_denied(self):
        for state in ('failure','skipped','cancelled',None):
            with self.subTest(state=state):
                data = fixture(); data['jobs'][0]['steps'][0]['conclusion'] = state
                with self.assertRaises(module.ReceiptError):
                    module.verify_run(data, SHA, 'golden')

    def test_no_required_step_or_job_is_denied(self):
        for key in ('jobs','steps'):
            data = fixture()
            if key=='jobs': data['jobs']=[]
            else: data['jobs'][0]['steps']=[]
            with self.subTest(key=key), self.assertRaises(module.ReceiptError):
                module.verify_run(data, SHA, 'golden')

    def test_wrong_origin_and_nonmain_are_denied(self):
        for key,val in [('url','https://attacker.test/actions/runs/123456789'),('databaseId',9876),('headBranch','feature'),('event','pull_request')]:
            data = fixture(); data[key]=val
            with self.subTest(key=key), self.assertRaises(module.ReceiptError):
                module.verify_run(data, SHA, 'golden')

    def test_missing_duplicate_required_step_and_bad_job_are_denied(self):
        data = fixture(); data['jobs'][0]['steps'].append(copy.deepcopy(data['jobs'][0]['steps'][0]))
        with self.assertRaises(module.ReceiptError): module.verify_run(data, SHA, 'golden')
        data = fixture(); data['jobs'][0]['conclusion']='failure'
        with self.assertRaises(module.ReceiptError): module.verify_run(data, SHA, 'golden')

    def test_oidc_requires_its_own_step(self):
        data = fixture()
        data['workflowName'] = 'Live OIDC service-account admission (non-production)'
        data['jobs'][0]['name'] = 'live-issuer'
        data['jobs'][0]['steps'][0]['name'] = 'Real issuer TLS + OAuth token issuance + catalog + PostgreSQL input admission'
        self.assertEqual(module.verify_run(data,SHA,'oidc')['required_job'],'live-issuer')
        with self.assertRaises(module.ReceiptError): module.verify_run(data,SHA,'golden')

    def test_malformed_types_fail_closed(self):
        for bad in (None, [], {'jobs':'fake'}, {'databaseId': True}):
            with self.subTest(bad=bad), self.assertRaises(module.ReceiptError):
                module.verify_run(bad,SHA,'golden')

    def test_ambiguous_duplicate_json_keys_fail_closed_at_cli_boundary(self):
        original = json.dumps(fixture())
        ambiguous = (
            original.replace(
                '"headSha": "' + SHA + '"',
                '"headSha": "' + ('b' * 40) + '", "headSha": "' + SHA + '"',
                1,
            ),
            original.replace(
                '"name": "e2e"',
                '"name": "not-the-acceptance-job", "name": "e2e"',
                1,
            ),
            original.replace(
                '"name": "' + GOLDEN_STEP + '"',
                '"conclusion": "failure", "name": "' + GOLDEN_STEP + '"',
                1,
            ),
        )
        for payload in ambiguous:
            with self.subTest(payload=payload[:130]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'run.json'
                path.write_text(payload, encoding='utf-8')
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = module.main([
                        '--run-json', str(path), '--expected-sha', SHA, '--scenario', 'golden',
                    ])
                self.assertEqual(code, 1, 'ambiguous evidence must be rejected')
                self.assertIn('"ok": false', err.getvalue().lower())
                self.assertEqual(out.getvalue(), '')

    def test_sha_validation(self):
        with self.assertRaises(module.ReceiptError): module.verify_run(fixture(), 'main','golden')
        with self.assertRaises(module.ReceiptError): module.verify_run(fixture(), SHA,'other')

if __name__=='__main__': unittest.main()
