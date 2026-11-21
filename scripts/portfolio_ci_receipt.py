#!/usr/bin/env python3
"""Fail-closed *metadata consistency check* for exported ACP GitHub Actions runs.

Input must be obtained by the reviewer from GitHub CLI; this does NOT
cryptographically authenticate the exported JSON or prove business behavior,
protected effects, independent approval, or production readiness.
"""

import argparse
import json
from pathlib import Path
import re
import sys

REPOSITORY = 'avaargsh/agent-control-panel'
SHA = re.compile(r'^[0-9a-f]{40}$')
RUN_URL = re.compile(r'^https://github\.com/avaargsh/agent-control-panel/actions/runs/([1-9][0-9]*)$')
SCENARIOS = {
    'golden': (
        'Same ACP Run to recovered Decision acceptance (non-production)',
        'e2e',
        'Execute live OAuth to same Run Temporal recovery and Decision acceptance',
    ),
    'oidc': (
        'Live OIDC service-account admission (non-production)',
        'live-issuer',
        'Real issuer TLS + OAuth token issuance + catalog + PostgreSQL input admission',
    ),
}


class ReceiptError(ValueError):
    """The supplied metadata cannot support even a narrow CI observation."""


def _required(condition, message):
    if not condition:
        raise ReceiptError(message)


def verify_run(run, expected_sha, scenario):
    """Validate exact-run metadata; never return an authorization attestation."""
    _required(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha), 'Expected an exact 40-character commit SHA')
    _required(scenario in SCENARIOS, 'Unknown acceptance scenario')
    _required(isinstance(run, dict), 'Run metadata must be a JSON object')
    workflow, job_name, step_name = SCENARIOS[scenario]

    run_id = run.get('databaseId')
    _required(type(run_id) is int and run_id > 0, 'Missing positive workflow run ID')
    url = run.get('url')
    url_match = RUN_URL.fullmatch(url) if isinstance(url, str) else None
    _required(url_match is not None and int(url_match.group(1)) == run_id, 'Run URL and ID do not bind the expected GitHub repository')
    _required(run.get('workflowName') == workflow, 'Unexpected workflow name')
    _required(run.get('headSha') == expected_sha, 'Wrong exact run commit SHA')
    _required(run.get('headBranch') == 'main', 'Demo must run against main')
    _required(run.get('event') == 'workflow_dispatch', 'Demo must be an explicitly dispatched workflow')
    _required(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Workflow did not complete successfully')
    attempt = run.get('attempt')
    _required(type(attempt) is int and attempt > 0, 'Missing positive workflow attempt')

    jobs = run.get('jobs')
    _required(isinstance(jobs, list) and bool(jobs), 'Missing workflow jobs')
    _required(all(isinstance(job, dict) and job.get('status') == 'completed' and job.get('conclusion') == 'success'
                  for job in jobs), 'At least one job was not completed successfully')
    selected = [job for job in jobs if job.get('name') == job_name]
    _required(len(selected) == 1, 'Required real integration job missing or duplicated')
    steps = selected[0].get('steps')
    _required(isinstance(steps, list), 'Missing job step evidence')
    relevant = [step for step in steps if isinstance(step, dict) and step.get('name') == step_name]
    _required(len(relevant) == 1, 'Required integration step missing or duplicated')
    _required(relevant[0].get('status') == 'completed' and relevant[0].get('conclusion') == 'success',
              'Required integration step did not complete successfully')

    return {
        'scenario': scenario,
        'repository': REPOSITORY,
        'run_id': run_id,
        'run_url': url,
        'attempt': attempt,
        'head_sha': expected_sha,
        'workflow': workflow,
        'required_job': job_name,
        'required_step': step_name,
        'grade': 'CI_METADATA_CHECK_ONLY',
        'production_accepted': False,
        'independently_attested': False,
        'warning': 'Exported JSON is not independently authenticated; inspect GitHub source, test logs, SHA pins and negative assertions separately.',
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-json', required=True, type=Path, help='File exported with gh run view --json')
    p.add_argument('--expected-sha', required=True, help='Full 40-character SHA expected at that run')
    p.add_argument('--scenario', required=True, choices=sorted(SCENARIOS))
    args = p.parse_args(argv)
    try:
        data = json.loads(args.run_json.read_text(encoding='utf-8'))
        result = verify_run(data, args.expected_sha, args.scenario)
    except (ReceiptError, ValueError, OSError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps({'ok': True, 'receipt': result}, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
