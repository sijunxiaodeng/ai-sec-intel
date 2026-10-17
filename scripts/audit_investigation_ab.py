"""Audit saved observable planner outputs, pair identity and source bytes."""
import argparse
import hashlib
import json
from pathlib import Path

CAPABILITIES = {
    'evidence.fetch': {'evidence_archive', 'cvss', 'affected_versions', 'source_conflict'},
    'enrichment.public_feeds': {'exploit_probability', 'known_exploitation'},
    'enrichment.papers': {'research_evidence'},
}


def audit(directory):
    report = json.loads((directory / 'report.json').read_text(encoding='utf-8'))
    totals = {'pairs': len(report['pairs']), 'same_input_pairs': 0, 'runs': 0,
              'executed_calls': 0, 'gap_compatible_calls': 0,
              'accepted_model_outputs_verified': 0, 'not_first_candidate_model_choices': 0,
              'hash_checked_http_responses': 0, 'frozen_provider_errors': 0,
              'single_candidate_control_model_calls': 0, 'errors': []}
    for pair in report['pairs']:
        initials = []
        for arm in ('rules', 'model'):
            folder = directory / 'runs' / pair['scenario'] / ('r' + str(pair['repetition'])) / arm
            initial = (folder / 'initial-record.json').read_bytes()
            initials.append(initial)
            result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
            metrics = json.loads((folder / 'metrics.json').read_text(encoding='utf-8'))
            io = json.loads((folder / 'model-io.json').read_text(encoding='utf-8'))
            trace = result['trace']
            totals['runs'] += 1
            if 'assessment_error' in trace.get('errors', []):
                totals['errors'].append('Assessment failed in ' + str(folder))
            if metrics.get('unverified_resolved_gaps'):
                totals['errors'].append('Unverified resolved gap in ' + str(folder))
            if len(trace['decisions']) != len(trace['calls']):
                totals['errors'].append('Decision / execution mismatch in ' + str(folder))
            successful_io = iter(x for x in io if x.get('status') == 'ok')
            for decision, call in zip(trace['decisions'], trace['calls']):
                totals['executed_calls'] += 1
                compatible = bool(CAPABILITIES.get(call['tool'], set()) & set(decision['gaps']))
                totals['gap_compatible_calls'] += compatible
                if not compatible or call['tool'] != decision['tool'] or call['tool'] not in decision['available_tools']:
                    totals['errors'].append('Tool incompatible with actual gap / execution in ' + str(folder))
                if decision['selected_by'] == 'model':
                    model_record = next(successful_io, None)
                    try:
                        chosen = json.loads(model_record['response'])
                        payload = json.loads(model_record['messages'][-1]['content'])
                        names = [v['name'] for v in payload['available_tools']]
                        valid = (set(chosen) == {'tool'} and chosen['tool'] == call['tool'] and
                                 names == decision['available_tools'] and payload['gaps'] == decision['gaps'])
                    except (TypeError, KeyError, ValueError):
                        valid = False
                    if valid:
                        totals['accepted_model_outputs_verified'] += 1
                        totals['not_first_candidate_model_choices'] += names[0] != chosen['tool']
                    else:
                        totals['errors'].append('Raw model output not matched to executed tool in ' + str(folder))
            if 'single-tool-control' == pair['scenario'] and arm == 'model':
                totals['single_candidate_control_model_calls'] += trace['model_calls']
            for path in metrics['sqlite_paths']:
                if not Path(path).resolve().is_relative_to(directory.resolve()):
                    totals['errors'].append('Nonisolated database: ' + path)
        if initials[0] == initials[1] and pair['rules']['initial_hash'] == pair['model']['initial_hash']:
            totals['same_input_pairs'] += 1
        else:
            totals['errors'].append('Mismatched initial state in ' + pair['scenario'])
    for path in (directory / 'http').glob('*.json'):
        meta = json.loads(path.read_text(encoding='utf-8'))
        if meta['status'] == 'ok':
            body = path.with_suffix('.body').read_bytes()
            if hashlib.sha256(body).hexdigest() != meta['response_sha256']:
                totals['errors'].append('Response hash mismatch: ' + path.name)
            else:
                totals['hash_checked_http_responses'] += 1
        else:
            totals['frozen_provider_errors'] += 1
    totals['status'] = 'passed' if not totals['errors'] else 'failed'
    return totals


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = audit(args.directory.resolve())
    (args.directory / 'artifact-audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(bool(result['errors']))
