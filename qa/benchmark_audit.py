"""Disposable signed-fixture benchmarks, never opens application databases."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time


DEV = Path(__file__).resolve().parent.parent
ARTIFACTS = DEV / '.test-data' / 'performance'


def rss_mib():
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            return round(int(line.split()[1]) / 1024, 2)


def peak_mib():
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)


def measure(function, repeats=3):
    results, elapsed = [], []
    for _ in range(repeats):
        started = time.perf_counter()
        results.append(function())
        elapsed.append(round((time.perf_counter() - started) * 1000, 3))
    return {'median_ms': round(statistics.median(elapsed), 3),
            'min_ms': min(elapsed), 'max_ms': max(elapsed), 'samples_ms': elapsed}, results


def benchmark(events, parent, contention=False):
    # Bounds apply only to this disposable benchmark and its scan children.
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (75, 75))
    from fastapi.testclient import TestClient
    from integrity_guard.api import create_app
    from integrity_guard.core import _json
    from integrity_guard.canonical import canonical_bytes, sha256
    token = 'isolated-performance-fixture-' + 'x' * 40
    timestamp = '2026-09-14T00:00:00.000+00:00'
    verdicts = ['VALID', 'INFECTED', 'CORRUPTED', 'REVIEW_REQUIRED', 'UNSCANNABLE']
    statuses = ['ALLOWED', 'BLOCKED', 'BLOCKED', 'FLAGGED', 'BLOCKED']
    with tempfile.TemporaryDirectory(prefix='mcp-guard-perf-', dir=parent) as temporary:
        directory = Path(temporary)
        app = create_app(directory, token=token, start_monitor=False)
        store, reports = app.state.store, app.state.reports
        result = {'events_seeded': events, 'filesystem_parent': str(parent),
                  'rss_empty_mib': rss_mib(), 'peak_empty_mib': peak_mib(),
                  'source_sha256': {name: hashlib.sha256((DEV / 'backend/integrity_guard' / name).read_bytes()).hexdigest()
                      for name in ['core.py', 'reports.py', 'api.py', 'scan_worker.py']}}
        previous = '0' * 64
        started = time.perf_counter()
        for index in range(events):
            number = index + 1
            verdict, status = verdicts[index % 5], statuses[index % 5]
            digest = sha256(('fixture-content-' + str(index // 2)).encode())
            filename = f'benchmark-{number:06d}.txt'
            identifier = f'benchmark-fixture-{number:08d}'
            score = 0 if verdict == 'VALID' else 90
            report = {'id': identifier, 'filename': filename, 'source_path': '/benchmark/files/' + filename,
                      'created_at': timestamp, 'sha256': digest, 'verdict': verdict, 'status': status,
                      'risk_score': score, 'severity': 'INFO' if score == 0 else 'HIGH',
                      'findings': [], 'analysis_complete': verdict not in {'CORRUPTED','UNSCANNABLE'},
                      'rules_version': 'benchmark-fixture', 'duration_ms': 0,
                      'extraction': {'format': 'txt', 'characters': 32, 'segments': 1, 'truncated': False},
                      'limitations': ['Synthetic performance fixture; not a scanned user file.']}
            reports.db.execute('INSERT INTO scans(id,created_at,report,verdict,sha256,filename,source_path,status) VALUES (?,?,?,?,?,?,?,?)',
                (identifier, timestamp, json.dumps(report), verdict, digest, filename, report['source_path'], status))
            payload = {'sequence': number, 'timestamp': timestamp, 'event_type': 'FILE_SCANNED',
                       'component_id': None, 'previous_hash': previous,
                       'details': {'scan_id': identifier, 'filename': filename, 'sha256': digest,
                                   'status': status, 'risk_score': score, 'verdict': verdict}}
            head = sha256(canonical_bytes(payload))
            document = {**payload, 'hash': head, 'signature': store._sign({'hash': head, 'sequence': number})}
            store._db.execute('INSERT INTO audit(sequence,document) VALUES (?,?)', (number, _json(document)))
            previous = head
        store._db.commit(); reports.db.commit()
        store._write_checkpoint(events, previous)
        result['fixture_ms'] = round((time.perf_counter() - started) * 1000, 3)
        result['rss_seeded_mib'] = rss_mib()
        result['db_bytes_seeded'] = sum(p.stat().st_size for p in directory.iterdir() if p.suffix in {'.sqlite3','.sqlite3-wal'} or p.name.endswith('-wal'))
        result['verify'], checks = measure(store.verify_audit)
        assert all(check['valid'] and check['checked'] == events for check in checks), checks
        result['verify_fast'], checks = measure(lambda: store.verify_audit(fast=True))
        assert all(check['valid'] and check['checked'] == events for check in checks), checks
        result['rss_verified_mib'] = rss_mib()
        result['get_policy'], policies = measure(store.get_policy)
        assert all(policy['version'] == 1 for policy in policies)
        result['scan_stats'], stats = measure(reports.stats)
        expected = {verdicts[i]: len(range(i, events, 5)) for i in range(5)}
        last = stats[-1]
        assert last['analyzed'] == events and last['unique_files'] == (events + 1) // 2
        assert last['valid'] == expected['VALID'] and last['infected'] == expected['INFECTED']
        assert last['corrupted'] == expected['CORRUPTED'] and last['unscannable'] == expected['UNSCANNABLE']
        assert last['review_required'] == expected['REVIEW_REQUIRED'] and last['matched'] == events
        assert last['blocked'] == sum(expected[name] for name in ['INFECTED','CORRUPTED','UNSCANNABLE'])
        assert reports.stats('INFECTED')['matched'] == expected['INFECTED']
        result['stats_checked'] = last
        result['scan_list_25'], pages = measure(lambda: reports.list(limit=25))
        assert all(len(page) == min(25, events) for page in pages)
        headers = {'Authorization': 'Bearer ' + token}
        with TestClient(app, base_url='http://127.0.0.1', headers=headers) as client:
            def status():
                response = client.get('/api/status'); response.raise_for_status()
                value = response.json()
                assert value['audit_valid'] and value['scans'] == events
                return value
            status()  # Warm the HTTP/threadpool path before timed repetitions.
            result['status_http'], unused = measure(status)
            extra_audit = 0
            if contention and events:
                from concurrent.futures import ThreadPoolExecutor
                import threading
                def pair(left, right):
                    barrier = threading.Barrier(2)
                    def timed(function):
                        barrier.wait(timeout=10)
                        start = time.perf_counter(); function()
                        return round((time.perf_counter() - start) * 1000, 3)
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        start = time.perf_counter()
                        first = executor.submit(timed, left)
                        second = executor.submit(timed, right)
                        return {'left_ms': first.result(timeout=30), 'right_ms': second.result(timeout=30),
                                'combined_wall_ms': round((time.perf_counter() - start) * 1000, 3)}
                result['concurrent_status_status'] = pair(status, status)
                result['concurrent_status_append'] = pair(status,
                    lambda: store.append_audit('PERFORMANCE_CONTENDED_APPEND', None, {'fixture': True}))
                extra_audit = 1
            result['append_audit'], unused = measure(lambda: store.append_audit('PERFORMANCE_APPEND', None, {'fixture': True}))
            def scan():
                response = client.post('/api/scan', files={'file': ('measured-normal.txt', b'Quarterly meeting notes for the current project.', 'text/plain')})
                response.raise_for_status()
                value = response.json()
                assert value['verdict'] == 'VALID' and value['analysis_complete'], value
                assert value['sandbox']['active'] is True, value
                return {'duration_ms_reported': value['duration_ms'], 'sandbox': value['sandbox']['mechanism']}
            result['scan_http'], result['scan_results'] = measure(scan)
            final = reports.stats()
            assert final['analyzed'] == events + 3 and final['valid'] == expected['VALID'] + 3
            assert final['unique_files'] == (events + 1) // 2 + 1
            final_check = store.verify_audit()
            assert final_check['valid'] and final_check['checked'] == events + 6 + extra_audit, final_check
            result['final_verified_events'] = final_check['checked']
            result['final_counters_valid'] = True
            result['rss_final_mib'] = rss_mib(); result['peak_final_mib'] = peak_mib()
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=int)
    parser.add_argument('--parent', default='/tmp')
    parser.add_argument('--sizes', default='0,100,1000,5000')
    parser.add_argument('--output', default=str(ARTIFACTS / 'baseline.json'))
    parser.add_argument('--contention', action='store_true')
    args = parser.parse_args()
    if args.events is not None:
        return benchmark(args.events, Path(args.parent), args.contention)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    records = []
    metadata = {'kernel': platform.release(), 'machine': platform.machine(), 'python': sys.version,
                'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'per_case_timeout_seconds': 90}
    for size in map(int, args.sizes.split(',')):
        print(f'Benchmark {size} signed events and {size} scan fixtures; timeout 90 s', flush=True)
        started = time.perf_counter()
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--events', str(size), '--parent', args.parent,
                                 *(['--contention'] if args.contention else [])],
                                 capture_output=True, timeout=90)
        if process.returncode:
            print(process.stderr.decode(errors='replace'), file=sys.stderr)
            raise SystemExit(process.returncode)
        result = json.loads(process.stdout)
        result['case_wall_seconds'] = round(time.perf_counter() - started, 3)
        records.append(result)
        Path(args.output).write_text(json.dumps({'environment': metadata, 'cases': records}, indent=2) + '\n')
        print(json.dumps({key: result[key] for key in ('events_seeded','verify','append_audit','status_http','scan_http','scan_stats','peak_final_mib','case_wall_seconds')}), flush=True)


if __name__ == '__main__':
    main()
