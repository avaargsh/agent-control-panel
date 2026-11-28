#!/usr/bin/env python3
"""Read-only conservative effective-rule preflight for GitHub main.

Never configures protection, approves a PR, merges, or proves there are no
bypass actors. Independent admin/UI verification remains mandatory.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

SHA = re.compile(r'^[a-f0-9]{40}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
DEFAULT_CONTEXTS = ('verify', 'contracts', 'evidence')
MANDATORY_RULES = frozenset(('pull_request', 'non_fast_forward', 'deletion', 'required_status_checks'))


def evaluate(branch, effective_rules, expected_main, expected_contexts=DEFAULT_CONTEXTS):
    """Return NO-GO reasons. Caller-supplied test snapshots are not attestations."""
    errors = []
    if not isinstance(branch, dict) or branch.get('name') != 'main':
        errors.append('missing or invalid main branch response')
        branch = {}
    if branch.get('protected') is not True:
        errors.append('main is not verified protected by the GitHub server')
    main_sha = (branch.get('commit') or {}).get('sha') if isinstance(branch.get('commit'), dict) else None
    if not isinstance(expected_main, str) or not SHA.fullmatch(expected_main) or main_sha != expected_main:
        errors.append('current main SHA differs from pinned audited SHA')
    if not isinstance(effective_rules, list) or not effective_rules:
        return errors + ['missing complete effective branch rules; 403 or [] is not success']
    if any(not isinstance(rule, dict) or not isinstance(rule.get('type'), str) for rule in effective_rules):
        return errors + ['malformed effective branch rule response']
    types = {rule['type'] for rule in effective_rules}
    for name in sorted(MANDATORY_RULES - types):
        errors.append('missing effective branch rule: ' + name)
    # Rulesets encode unresolved PR conversation blocking inside the
    # pull_request rule's parameters. A bare pull_request rule does not
    # enforce this policy; fail closed rather than inferring it.
    pr_rules = [rule for rule in effective_rules if rule['type'] == 'pull_request']
    if not any(isinstance(rule.get('parameters'), dict) and
               rule['parameters'].get('required_review_thread_resolution') is True
               for rule in pr_rules):
        errors.append('required review thread conversation resolution is not confirmed')
    checks = [rule for rule in effective_rules if rule['type'] == 'required_status_checks']
    if len(checks) != 1:
        errors.append('required_status_checks rule must be unambiguous')
        return errors
    params = checks[0].get('parameters')
    if not isinstance(params, dict) or params.get('strict_required_status_checks_policy') is not True:
        errors.append('strict current-branch status checks are not confirmed')
        return errors
    required = params.get('required_status_checks')
    if not isinstance(required, list) or not required:
        errors.append('missing actual required status job contexts')
        return errors
    names = [x.get('context') if isinstance(x, dict) else None for x in required]
    if any(not isinstance(x, str) or not x for x in names) or len(names) != len(set(names)):
        errors.append('invalid, duplicate, or ambiguous required job contexts')
    if not isinstance(expected_contexts, (tuple, list)) or not expected_contexts:
        errors.append('missing expected required job contexts')
    else:
        missing = set(expected_contexts) - {x for x in names if isinstance(x, str)}
        if missing:
            errors.append('missing required job contexts: ' + ', '.join(sorted(missing)))
    return errors


def fetch(repo, path, token):
    request = urllib.request.Request('https://api.github.com/repos/' + repo + path, headers={
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Authorization': 'Bearer ' + token,
        'User-Agent': 'acp-readonly-main-rules-audit',
    })
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def fetch_all_effective_rules(repo, token, getter=None, max_pages=20):
    """Fetch every effective branch rule or fail closed on incomplete pages."""
    if getter is None:
        getter = fetch
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError('invalid effective rules page bound')
    collected = []
    for page in range(1, max_pages + 1):
        entries = getter(repo, '/rules/branches/main?per_page=100&page=' + str(page), token)
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError('malformed effective branch rules page')
        collected.extend(entries)
        if len(entries) < 100:
            return collected
    # The last full page may conceal additional restrictions. No partial PASS.
    raise ValueError('effective rules pagination exceeded bound')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only main rules evidence; never merges')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--expected-main', required=True, help='full 40-digit pinned SHA')
    args = parser.parse_args(argv)
    if not REPO.fullmatch(args.repository) or not SHA.fullmatch(args.expected_main):
        print('MAIN_PROTECTION_AUDIT=BLOCKED: invalid target', file=sys.stderr)
        return 2
    token = os.environ.get('ACP_GOVERNANCE_READ_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not token:
        print('MAIN_PROTECTION_AUDIT=BLOCKED: read-only GitHub credentials required', file=sys.stderr)
        return 2
    try:
        branch = fetch(args.repository, '/branches/main', token)
        rules = fetch_all_effective_rules(args.repository, token)
        errors = evaluate(branch, rules, args.expected_main)
        if not errors:
            # Rule pagination and branch reads are not atomic. Do not label a
            # visibly changed branch as verified at the originally pinned SHA.
            current_branch = fetch(args.repository, '/branches/main', token)
            errors = evaluate(current_branch, rules, args.expected_main)
    except (OSError, ValueError, KeyError, TypeError, urllib.error.HTTPError):
        print('MAIN_PROTECTION_AUDIT=BLOCKED: GitHub rules authority inaccessible or incomplete', file=sys.stderr)
        return 2
    if errors:
        for reason in errors:
            print('BLOCKED: ' + reason, file=sys.stderr)
        print('MAIN_PROTECTION_AUDIT=BLOCKED', file=sys.stderr)
        return 1
    print('MAIN_RULES_OBSERVED_AT_PINNED_SHA_ONLY; VERIFY_BYPASS_AND_HUMAN_APPROVAL_SEPARATELY')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
