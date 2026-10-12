#!/usr/bin/env python3
"""Author literal expected fixtures from the declared semantics only.

This script does not import, invoke, inspect, or compare the candidate, generated
code, verifier, host implementation, or native execution output.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTRACT = Path('/Users/alice/meta-go/output/growth/completion-ledger-20261013/implementation-contract.json')
REA_SOURCE = Path('/Users/alice/meta-go/research/rea-analysis-20261013/source/src/domain/evidenceCompletionLedger.ts')
STATUSES = ('pass', 'fail', 'unsupported', 'truncated', 'unknown')
COUNT_FIELDS = ('total', *STATUSES)
MAX = (1 << 63) - 1
MIN = -(1 << 63)
STEP = 'gooo/completion-ledger:CompletionStep'
FINISH = 'gooo/completion-ledger:CompletionFinish'
READY = 'gooo/completion-ledger:CompletionReady'
G_SCHEMA = 'gooo/body-composition-cases/v1'
entries = []
books = {}


def counts(*values):
    assert len(values) == 5
    return {'total': sum(values), **dict(zip(STATUSES, values))}


def consistent(c):
    # Arbitrary-precision authoring arithmetic establishes the mathematical
    # invariant independently of the candidate's guarded int64 subtraction.
    return all(c[field] >= 0 for field in COUNT_FIELDS) and sum(c[s] for s in STATUSES) == c['total']


def invalid(reason):
    return {**counts(0, 0, 0, 0, 0), 'valid': False, 'complete': False, 'reason': reason}


def step(c, status):
    if not consistent(c):
        return invalid('INVALID_COUNTS')
    if status not in STATUSES:
        return invalid('INVALID_STATUS')
    if c['total'] == MAX:
        return invalid('COUNTER_CAPACITY')
    after = dict(c)
    after['total'] += 1
    after[status] += 1
    return {**after, 'valid': True, 'complete': after['pass'] == after['total'], 'reason': 'ACCUMULATED'}


def finish(c):
    if not consistent(c):
        return invalid('INVALID_COUNTS')
    if c['total'] == 0:
        return invalid('NO_RECORDS')
    complete = c['pass'] == c['total']
    return {**c, 'valid': True, 'complete': complete, 'reason': 'ALL_PASS' if complete else 'NON_PASS_RESULTS'}


def readiness(summary, coverage):
    cc = consistent(summary)
    required = coverage['required_count']
    matched = coverage['matched_count']
    unexpected = coverage['unexpected_count']
    observed = coverage['observed_count']
    facts = (required > 0 and matched >= 0 and unexpected >= 0 and observed >= 0
             and matched <= required and observed >= matched and observed - matched == unexpected)
    flags = {
        'counts_ok': cc and facts,
        'coverage_ok': facts and matched == required and unexpected == 0,
        'summary_ok': (summary['valid'] and summary['total'] > 0 and summary['total'] == observed
                       and summary['complete'] == (summary['pass'] == summary['total'])),
        'all_pass_ok': cc and summary['total'] > 0 and summary['pass'] == summary['total'] and summary['complete'],
    }
    ready = all(flags.values())
    priority = (('counts_ok', 'INVALID_COUNTS'), ('coverage_ok', 'INCOMPLETE_CLAIM_COVERAGE'),
                ('summary_ok', 'INVALID_COMPLETION_SUMMARY'), ('all_pass_ok', 'NON_PASS_RESULTS'))
    reason = next((reason for flag, reason in priority if not flags[flag]), 'READY')
    return {'ready': ready, 'reason': reason, **flags}


def add(book, name, family, inputs, expected):
    index = len(books[book]['cases'])
    books[book]['cases'].append({'inputs': inputs, 'expected': expected})
    entries.append({'book': book, 'index': index, 'id': f'{book.removesuffix("-cases.json")}-{index:05d}',
                    'name': name, 'family': family})


def compositions(total, slots=5):
    if slots == 1:
        yield (total,)
        return
    for first in range(total + 1):
        for rest in compositions(total - first, slots - 1):
            yield (first, *rest)


states = [counts(*parts) for total in range(5) for parts in compositions(total)]
assert len(states) == 126
for book in ('step-cases.json', 'finish-cases.json', 'ready-cases.json'):
    books[book] = {'schema': G_SCHEMA, 'cases': []}

for c in states:
    label = ','.join(str(c[f]) for f in COUNT_FIELDS)
    for status in STATUSES:
        add('step-cases.json', f'consistent ({label}) then {status}', 'consistent-total-0-through-4',
            {STEP + '.input0': c, STEP + '.input1': status}, step(c, status))
    add('finish-cases.json', f'finish consistent ({label})', 'consistent-total-0-through-4',
        {FINISH: c}, finish(c))

# Counter domains are generic; all consistent boundaries remain valid until the
# next increment would exceed int64. No four-record or host-size cap is applied.
boundaries = []
for magnitude in (5, 255, 256, 257, 1000000, MAX - 1, MAX):
    for counter_index, status in enumerate(STATUSES):
        values = [0] * 5
        values[counter_index] = magnitude
        boundaries.append((f'{status} only total {magnitude}', counts(*values)))
boundaries.extend([
    ('balanced int64 maximum', counts(MAX // 5, MAX // 5, MAX // 5, MAX // 5, MAX - 4 * (MAX // 5))),
    ('mixed int64 maximum minus one', counts(MAX - 5, 1, 1, 1, 1)),
    ('mixed total five', counts(1, 1, 1, 1, 1)),
    ('mixed total 256', counts(52, 51, 51, 51, 51)),
    ('mixed total 257', counts(53, 51, 51, 51, 51)),
])
for label, c in boundaries:
    assert consistent(c)
    for status in STATUSES:
        add('step-cases.json', label + ' then ' + status, 'generic-and-int64-boundaries',
            {STEP + '.input0': c, STEP + '.input1': status}, step(c, status))
    add('finish-cases.json', 'finish ' + label, 'generic-and-int64-boundaries', {FINISH: c}, finish(c))

invalid_counts = []
for field in COUNT_FIELDS:
    for negative in (-1, MIN):
        c = counts(0, 0, 0, 0, 0)
        c[field] = negative
        invalid_counts.append((f'negative {field} {negative}', c))
invalid_counts.extend([
    ('total under sum', {'total': 1, 'pass': 1, 'fail': 1, 'unsupported': 0, 'truncated': 0, 'unknown': 0}),
    ('total over sum', {'total': 2, 'pass': 1, 'fail': 0, 'unsupported': 0, 'truncated': 0, 'unknown': 0}),
    ('zero total with positive result', {'total': 0, 'pass': 0, 'fail': 0, 'unsupported': 0, 'truncated': 0, 'unknown': 1}),
    ('positive total with zero result', {'total': 1, 'pass': 0, 'fail': 0, 'unsupported': 0, 'truncated': 0, 'unknown': 0}),
    ('int64 sum exceeds max at second counter', {'total': MAX, 'pass': MAX, 'fail': 1, 'unsupported': 0, 'truncated': 0, 'unknown': 0}),
    ('int64 sum exceeds max at final counter', {'total': MAX, 'pass': 0, 'fail': 0, 'unsupported': 0, 'truncated': MAX, 'unknown': 1}),
    ('all counters maximum overflow', {'total': MAX, 'pass': MAX, 'fail': MAX, 'unsupported': MAX, 'truncated': MAX, 'unknown': MAX}),
    ('int64 sum under total by one', {'total': MAX, 'pass': MAX - 1, 'fail': 0, 'unsupported': 0, 'truncated': 0, 'unknown': 0}),
    ('canceling negative remains invalid', {'total': 1, 'pass': 1, 'fail': -1, 'unsupported': 1, 'truncated': 0, 'unknown': 0}),
    ('int64 minimum canceling max', {'total': 0, 'pass': MIN, 'fail': MAX, 'unsupported': 1, 'truncated': 0, 'unknown': 0}),
])
for label, c in invalid_counts:
    assert not consistent(c)
    for status in (*STATUSES, 'PASS'):
        add('step-cases.json', label + ' then ' + status, 'invalid-counts-and-priority',
            {STEP + '.input0': c, STEP + '.input1': status}, step(c, status))
    add('finish-cases.json', 'finish ' + label, 'invalid-counts', {FINISH: c}, finish(c))

invalid_statuses = ('', 'PASS', 'Pass', 'Fail', ' pass', 'pass ', 'pass\n', 'pass\t', 'pass\u0000',
                    'passed', 'failure', 'UNSUPPORTED', 'unsupported ', 'truncation', 'UNKNOWN',
                    'unknown\r', 'pending', '0', 'true', 'pass/fail', '\U0001f7e2')
for status in invalid_statuses:
    for label, c in [('zero', counts(0, 0, 0, 0, 0)), ('nonempty', counts(1, 0, 0, 0, 0)),
                     ('at capacity', counts(MAX, 0, 0, 0, 0))]:
        add('step-cases.json', label + ' invalid exact label ' + repr(status), 'invalid-exact-status-and-priority',
            {STEP + '.input0': c, STEP + '.input1': status}, step(c, status))

# Readiness flag expectations are independent: deliberately inconsistent
# summary flags and invalid coverage facts are combined rather than short-cut.
summary_count_vectors = [
    ('empty', counts(0, 0, 0, 0, 0)),
    ('all pass one', counts(1, 0, 0, 0, 0)),
    ('all fail one', counts(0, 1, 0, 0, 0)),
    ('unsupported one', counts(0, 0, 1, 0, 0)),
    ('truncated one', counts(0, 0, 0, 1, 0)),
    ('unknown one', counts(0, 0, 0, 0, 1)),
    ('all pass two', counts(2, 0, 0, 0, 0)),
    ('pass fail two', counts(1, 1, 0, 0, 0)),
    ('all pass 257', counts(257, 0, 0, 0, 0)),
    ('all pass int64 maximum', counts(MAX, 0, 0, 0, 0)),
    ('all fail int64 maximum', counts(0, MAX, 0, 0, 0)),
    ('mixed int64 maximum', counts(MAX - 1, 1, 0, 0, 0)),
    *invalid_counts,
]
coverage_vectors = [
    ('perfect one', (1, 1, 0, 1)),
    ('perfect two', (2, 2, 0, 2)),
    ('perfect 257', (257, 257, 0, 257)),
    ('perfect int64 maximum', (MAX, MAX, 0, MAX)),
    ('missing one of two', (2, 1, 0, 1)),
    ('all required missing', (1, 0, 0, 0)),
    ('required and unexpected', (1, 1, 1, 2)),
    ('only unexpected', (1, 0, 1, 1)),
    ('missing and unexpected', (2, 1, 1, 2)),
    ('zero required', (0, 0, 0, 0)),
    ('zero required observed', (0, 0, 1, 1)),
    ('negative required', (-1, 0, 0, 0)),
    ('minimum required', (MIN, 0, 0, 0)),
    ('negative matched', (1, -1, 1, 0)),
    ('minimum matched', (1, MIN, MAX, 0)),
    ('negative unexpected', (1, 1, -1, 0)),
    ('minimum unexpected', (1, 1, MIN, 1)),
    ('negative observed', (1, 0, 0, -1)),
    ('minimum observed', (1, 0, 0, MIN)),
    ('matched above required', (1, 2, 0, 2)),
    ('observed below matched', (2, 2, 0, 1)),
    ('underreported unexpected', (1, 1, 0, 2)),
    ('overreported unexpected', (1, 1, 2, 2)),
    ('unmatched observed difference invalid', (1, 0, 0, 1)),
    ('maximum observed only unexpected', (1, 0, MAX, MAX)),
    ('maximum observed one matched', (1, 1, MAX - 1, MAX)),
    ('maximum difference wrong by one', (1, 1, MAX, MAX)),
    ('maximum matched plus unexpected overflow', (MAX, MAX, 1, MAX)),
    ('maximum observed below maximum matched', (MAX, MAX, 0, MAX - 1)),
    ('maximum missing one', (MAX, MAX - 1, 0, MAX - 1)),
]
for summary_label, c in summary_count_vectors:
    for valid, complete in itertools.product((False, True), repeat=2):
        summary = {**c, 'valid': valid, 'complete': complete, 'reason': 'INDEPENDENT_LITERAL_REASON'}
        for coverage_label, values in coverage_vectors:
            coverage = dict(zip(('required_count', 'matched_count', 'unexpected_count', 'observed_count'), values))
            add('ready-cases.json', f'{summary_label}; valid={valid}; complete={complete}; {coverage_label}',
                'independent-flags-and-boundary-cross-product',
                {READY + '.input0': summary, READY + '.input1': coverage}, readiness(summary, coverage))

# Host cases are full semantic CLI expectations, with dynamic bindings omitted
# explicitly: their actual source/policy byte digests must be checked separately.
host = {'schema': 'policy-studio/completion-host-cases/v1', 'cases': []}
books['host-cases.json'] = host


def evidence(number=0):
    return 'ev_' + format(number, '064x')


def policy(claim_ids, number, revision=1):
    return {'schema': 'policy-studio/completion-policy/v1', 'policy_id': f'completion_policy_{number:04d}',
            'revision': revision, 'required_claims': list(claim_ids)}


def record(claim_id, status, evidence_ids=None):
    return {'claim_id': claim_id, 'status': status, 'evidence_ids': list(evidence_ids or [evidence(0)])}


def host_case(name, family, selected_policy, request_input):
    c = counts(0, 0, 0, 0, 0)
    steps = []
    for index, r in enumerate(request_input['records']):
        d = step(c, r['status'])
        steps.append({'index': index, 'counts_before': dict(c), 'status': r['status'], 'decision': d})
        c = {field: d[field] for field in COUNT_FIELDS}
    summary = finish(c)
    required = set(selected_policy['required_claims'])
    observed = {r['claim_id'] for r in request_input['records']}
    matched = len(observed & required)
    unexpected = sorted(observed - required)
    missing = sorted(required - observed)
    coverage = {'required_count': len(required), 'matched_count': matched,
                'unexpected_count': len(unexpected), 'observed_count': len(request_input['records'])}
    ready = readiness(summary, coverage)
    report = {'schema': 'policy-studio/completion-report/v1', 'policy': selected_policy, 'input': request_input,
              'steps': steps, 'summary': summary, 'coverage': coverage,
              'missing_claims': missing, 'unexpected_claims': unexpected, 'readiness': ready}
    index = len(host['cases'])
    host['cases'].append({'policy': selected_policy, 'input': request_input,
                          'expected': {'exit_code': 0 if ready['ready'] else 1, 'report': report}})
    entries.append({'book': 'host-cases.json', 'index': index, 'id': f'host-{index:05d}',
                    'name': name, 'family': family})


sequence_count = 0
for length in range(1, 5):
    for sequence in itertools.product(STATUSES, repeat=length):
        claim_ids = [f'claim_{i:03d}' for i in range(length)]
        selected_policy = policy(claim_ids, sequence_count)
        request_input = {'schema': 'policy-studio/completion-input/v1', 'request_id': f'request_{sequence_count:04d}',
                         'records': [record(claim_id, status) for claim_id, status in zip(claim_ids, sequence)]}
        host_case('ordered sequence ' + ','.join(sequence), 'all-ordered-status-sequences-length-1-through-4',
                  selected_policy, request_input)
        sequence_count += 1
assert sequence_count == 780


def special(name, claims, records, revision=1):
    number = len(host['cases'])
    host_case(name, 'host-empty-coverage-order-and-size-boundaries', policy(claims, number, revision),
              {'schema': 'policy-studio/completion-input/v1', 'request_id': f'boundary_request_{number:04d}', 'records': records})


special('empty observations with one required claim', ['claim_empty'], [])
special('empty observations with 256 required claims', [f'claim_{i:03d}' for i in range(256)], [])
special('one missing claim all observed pass', ['claim_a', 'claim_b'], [record('claim_a', 'pass')])
special('all required claims missing only unexpected pass', ['claim_a', 'claim_b'], [record('claim_x', 'pass')])
special('one unexpected claim all outcomes pass', ['claim_a'], [record('claim_a', 'pass'), record('claim_x', 'pass')])
special('missing and unexpected claims sorted independently', ['claim_z', 'claim_b', 'claim_a'],
        [record('claim_y', 'pass'), record('claim_z', 'pass'), record('claim_x', 'pass')])
special('missing coverage wins over nonpass results', ['claim_a', 'claim_b'], [record('claim_a', 'fail')])
special('unexpected coverage wins over nonpass results', ['claim_a'], [record('claim_x', 'unknown'), record('claim_a', 'pass')])
special('input and policy order preserved', ['claim_z', 'claim_a', 'claim_m'],
        [record('claim_m', 'pass'), record('claim_z', 'unsupported'), record('claim_a', 'truncated')])
special('shared evidence across different claims is valid', ['claim_b', 'claim_a'],
        [record('claim_b', 'pass', [evidence(99)]), record('claim_a', 'pass', [evidence(99)])])
special('evidence input order preserved', ['claim_a'], [record('claim_a', 'pass', [evidence(2), evidence(1), evidence(0)])])
special('256 evidence ids on one claim', ['claim_a'], [record('claim_a', 'pass', [evidence(i) for i in reversed(range(256))])])
# Exactly 80 ASCII characters for every host identifier category.
number = len(host['cases'])
long_policy = {'schema': 'policy-studio/completion-policy/v1', 'policy_id': 'p' * 80,
               'revision': MAX, 'required_claims': ['c' * 80]}
long_input = {'schema': 'policy-studio/completion-input/v1', 'request_id': 'r' * 80,
              'records': [record('c' * 80, 'pass')]}
host_case('ASCII identifiers at 80 characters and positive maximum revision',
          'host-empty-coverage-order-and-size-boundaries', long_policy, long_input)
special('one character ASCII identifiers', ['c'], [record('c', 'pass')])
claim_ids_256 = [f'claim_{i:03d}' for i in range(256)]
for status in STATUSES:
    special(f'256 records all {status}', list(reversed(claim_ids_256)),
            [record(claim, status) for claim in reversed(claim_ids_256)])
special('256 records mixed all exact statuses', claim_ids_256,
        [record(claim, STATUSES[i % 5]) for i, claim in enumerate(reversed(claim_ids_256))])
special('256 records one nonpass at final position', claim_ids_256,
        [record(claim, 'fail' if i == 255 else 'pass') for i, claim in enumerate(claim_ids_256)])
special('256 records one unexpected and one missing', claim_ids_256,
        [record(claim, 'pass') for claim in claim_ids_256[:-1]] + [record('claim_unexpected', 'pass')])
special('256 records all unexpected with 256 required claims', claim_ids_256,
        [record(f'unexpected_{i:03d}', 'pass') for i in reversed(range(256))])


def serialize(value):
    return (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode('utf-8')


book_records = []
for name, value in books.items():
    raw = serialize(value)
    (ROOT / name).write_bytes(raw)
    families = {}
    for entry in entries:
        if entry['book'] == name:
            families[entry['family']] = families.get(entry['family'], 0) + 1
    book_records.append({'file': name, 'schema': value['schema'], 'case_count': len(value['cases']),
                         'byte_count': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'families': families})

flag_patterns = sorted({tuple(c['expected'][key] for key in ('counts_ok', 'coverage_ok', 'summary_ok', 'all_pass_ok'))
                        for c in books['ready-cases.json']['cases']})
assert len(flag_patterns) == 14
reason_counts = {}
for case in books['ready-cases.json']['cases']:
    reason = case['expected']['reason']
    reason_counts[reason] = reason_counts.get(reason, 0) + 1

catalog = {
    'schema': 'policy-studio/completion-fixture-catalog/v1',
    'status': 'INDEPENDENT_EXPECTATION_AUTHORSHIP_NOT_NATIVE_ACCEPTANCE',
    'authorship': {
        'method': 'Literal expected values serialized from independent Python mathematical semantics derived only from declared contract and original pinned Rea source.',
        'candidate_implementation_read': False,
        'generated_go_read': False,
        'host_implementation_read': False,
        'verifier_read': False,
        'actual_execution_output_read': False,
        'native_execution_performed': False,
        'build_or_test_performed': False,
        'network_performed': False,
        'scope': 'Authorship and fixture integrity only; this catalog is not native acceptance or execution evidence.',
    },
    'provenance': [
        {'role': 'declared semantic contract', 'path': str(CONTRACT), 'sha256': hashlib.sha256(CONTRACT.read_bytes()).hexdigest()},
        {'role': 'pinned original Rea source', 'path': str(REA_SOURCE), 'source_commit': '8fc2043eb8bcedbf34dce064f977e455438635d6',
         'sha256': hashlib.sha256(REA_SOURCE.read_bytes()).hexdigest()},
    ],
    'core_input_key_contract': {
        'step': [STEP + '.input0', STEP + '.input1'], 'finish': [FINISH],
        'ready': [READY + '.input0', READY + '.input1'],
        'books': 'Exactly schema and cases at top level; exactly inputs and expected per case. IDs and names exist only in this catalog.',
    },
    'host_case_contract': {
        'schema': host['schema'], 'case_fields': ['policy', 'input', 'expected'],
        'expected_fields': ['exit_code', 'report'],
        'report_fields': ['schema', 'policy', 'input', 'steps', 'summary', 'coverage', 'missing_claims', 'unexpected_claims', 'readiness'],
        'bindings': 'Dynamic raw policy, source, generated code, bridge, and generation digests deliberately excluded; consumer must check independently against actual bytes.',
        'policy_separation': 'Policy is a separate case field and is never included in the regular input payload.',
    },
    'coverage': {
        'finite_domain_is_not_api_limit': True,
        'consistent_counter_states_total_0_through_4': 126,
        'exact_status_count': 5,
        'exhaustive_step_domain_cases': 630,
        'exhaustive_finish_domain_cases': 126,
        'ordered_host_sequences_length_1_through_4': 780,
        'int64_boundaries': {'minimum': MIN, 'maximum': MAX},
        'readiness_flag_order': ['counts_ok', 'coverage_ok', 'summary_ok', 'all_pass_ok'],
        'readiness_attainable_flag_patterns': [list(p) for p in flag_patterns],
        'readiness_reason_counts': reason_counts,
        'readiness_independence': 'All 14 attainable four-flag patterns are present. The two missing patterns require counts_ok=false, coverage_ok=true, all_pass_ok=true and are impossible under the declared invariants.',
        'host_size_and_identifier_boundaries': ['zero observed records', '256 observed records', '256 required claims', '256 evidence ids per record', '80-character ASCII identifiers', 'positive int64 maximum revision', 'same evidence reused across distinct claims', 'unsorted original input and policy order'],
        'public_empty_boundary': 'CompletionFinish returns NO_RECORDS for valid zero counts; this extension does not claim private Rea summarize([]) equivalence.',
    },
    'books': book_records,
    'case_catalog': entries,
}
(ROOT / 'catalog.json').write_bytes(serialize(catalog))
print(json.dumps({'books': book_records, 'catalog_case_count': len(entries),
                  'readiness_flag_pattern_count': len(flag_patterns), 'readiness_reason_counts': reason_counts}, indent=2))
