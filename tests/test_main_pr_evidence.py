import unittest

from scripts.check_main_pr_evidence import validate

BASE = 'a' * 40
HEAD = 'b' * 40


def event(text, *, head=HEAD, base=BASE, draft=False, base_ref='main'):
    return {'pull_request': {
        'number': 44, 'draft': draft, 'body': text,
        'base': {'ref': base_ref, 'sha': base},
        'head': {'sha': head},
    }}


def body(*, base=BASE, head=HEAD):
    return f'''# Summary

Review-only change to governance checks.

## Governance metadata

- Target branch (main or internal feature parent); exact base/head commit SHAs: main base={base} head={head}
- Change class (docs-only / contract / migration / runtime / protected effect / provider): docs-only
- Affected domain / sole authoritative writer: ACP owns RunIntent; Runtime owns Run
- Governance gate(s): none; documentation only, G01-G05 not claimed

## Evidence (link real CI runs)

- Test/CI evidence at exact HEAD (run URL or explicit no-workflow reason): no workflow on prior main; test-only validation
- Authorization/recovery negative-case evidence or explained N/A: N/A because only documentation is changed

## Delivery / rollback

- Remaining blockers and explicit non-goals: G01-G05 live acceptance remains UNKNOWN
- Backward compatibility and rollback: revert this Markdown-only commit
- Main promotion vs internal-only merge decision, with rationale: main, documentation only and no runtime behavior
- Required GitHub branch rules/required status checks verified independently (or current status UNKNOWN): UNKNOWN, connector lacks ruleset read
'''


class EvidenceTests(unittest.TestCase):
    def test_complete_declaration(self):
        self.assertEqual(validate(event(body())), [])

    def test_draft_skips_without_promotion(self):
        self.assertEqual(validate(event('', draft=True)), [])

    def test_other_base_unaffected(self):
        self.assertEqual(validate(event('', base_ref='feature/safety')), [])

    def test_stale_head_rejected(self):
        self.assertTrue(any('head' in e.lower()
                            for e in validate(event(body(head='c' * 40)))))

    def test_stale_base_rejected(self):
        self.assertTrue(any('base' in e.lower()
                            for e in validate(event(body(base='c' * 40)))))

    def test_blank_template_rejected(self):
        incomplete = '## Governance metadata\n\n- Affected domain / sole authoritative writer:\n'
        self.assertGreaterEqual(len(validate(event(incomplete))), 4)

    def test_todo_placeholder_rejected(self):
        text = body().replace('docs-only\n- Affected domain', 'TODO\n- Affected domain')
        self.assertTrue(validate(event(text)))

    def test_unexplained_na_rejected(self):
        text = body().replace('N/A because only documentation is changed', 'N/A')
        self.assertTrue(validate(event(text)))

    def test_missing_pr_fails_closed(self):
        self.assertTrue(validate({}))

    def test_malformed_head_fails_closed(self):
        self.assertTrue(validate(event(body(), head='invalid')))

    def test_unverified_rulesets_can_be_explicitly_unknown(self):
        self.assertEqual(validate(event(body())), [])

    def test_s3_manual_acceptance_requires_main_ref_before_environment_secrets(self):
        from pathlib import Path

        content = (Path(__file__).resolve().parents[1] / '.github' / 'workflows'
                   / 'workspace-writeonce-approved.yml').read_text(encoding='utf-8')
        self.assertIn('  validate-acceptance-ref:', content)
        self.assertIn('    needs: validate-acceptance-ref', content)
        self.assertIn("    if: github.ref == 'refs/heads/main'", content)
        self.assertIn('test "$GITHUB_REF" = "refs/heads/main"', content)

    def test_s3_manual_acceptance_requires_exact_dispatch_commit(self):
        from pathlib import Path

        content = (Path(__file__).resolve().parents[1] / '.github' / 'workflows'
                   / 'workspace-writeonce-approved.yml').read_text(encoding='utf-8')
        self.assertIn('      expected_sha:', content)
        self.assertIn('          APPROVED_SHA: ${{ inputs.expected_sha }}', content)
        self.assertIn('[[ "$APPROVED_SHA" =~ ^[0-9a-f]{40}$ ]]', content)
        self.assertIn('test "$GITHUB_SHA" = "$APPROVED_SHA"', content)
        self.assertIn('          ref: ${{ inputs.expected_sha }}', content)
        self.assertIn('test "$(git rev-parse HEAD)" = "$APPROVED_SHA"', content)

    def test_s3_manual_acceptance_checkout_does_not_persist_token(self):
        from pathlib import Path

        content = (Path(__file__).resolve().parents[1] / '.github' / 'workflows'
                   / 'workspace-writeonce-approved.yml').read_text(encoding='utf-8')
        self.assertIn('          persist-credentials: false', content)



if __name__ == '__main__':
    unittest.main()
