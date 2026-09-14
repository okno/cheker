#!/usr/bin/env python3
"""Separate soak for the frozen final-features package, adding benign HTML copies.

The baseline soak remains unmodified. Each cycle also submits one deterministic
UTF-8 HTML document, validates the exact delivered bytes, remembers both reports,
and checks every page of the metadata ledger. Every restart rechecks all linked
historical report hashes. No document bodies, credentials or response bodies are
written to logs. The same owned-process cleanup and first-error failure rules
apply. Duration covers the exercise loop; an in-flight cycle and a restart's
history check each have a separate 180-second budget, plus startup/shutdown.

Run a short functional check, not a long run:
  python3 qa/soak_features.py --python /path/to/runtime-linux/bin/python \
    --data-root /tmp/.test-data/features-new --duration 180 --interval .1 --restart-every 4
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import time

BASELINE_SHA256 = '3c37b465c5c3d3faee0b47140c3b2ba9d32f5c78ccc6ceaea2e2186b3d3c316a'
PAGE_SIZE = 10  # Explicit API query; intentionally crosses a page in the short check.
MAX_OPERATIONS = 20_000
MAX_COPY_BYTES = 256 * 1024
METADATA_KEYS = {'id', 'created_at', 'profile', 'transformation_status', 'delivery_status', 'reason',
                 'input_filename', 'output_filename', 'input_sha256', 'output_sha256', 'input_size_bytes',
                 'output_size_bytes', 'input_report_id', 'output_report_id', 'omitted_counts'}
COUNT_KEYS = {'comments', 'hidden_nodes', 'metadata_nodes', 'active_nodes', 'nontext_nodes', 'attributes'}


def baseline_module():
    path = Path(__file__).resolve().with_name('soak.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != BASELINE_SHA256:
        raise RuntimeError('Baseline soak source changed; review the separate runner before use')
    spec = importlib.util.spec_from_file_location('_cheker_baseline_soak_features', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


baseline = baseline_module()
require = baseline.require
InvariantError = baseline.InvariantError


def fixture(cycle):
    heading = 'Note del progetto ' + str(cycle)
    paragraph = 'Caffè e tè: revisione lunedì.'
    return (('<article><h1>' + heading + '</h1><p>' + paragraph + '</p></article>').encode('utf-8'),
            (heading + '\n' + paragraph + '\n').encode('utf-8'), 'notes-' + str(cycle) + '.html')


def metadata_digest(metadata):
    encoded = json.dumps(metadata, sort_keys=True, ensure_ascii=True, allow_nan=False,
                         separators=(',', ':')).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def validate_metadata(metadata):
    require(type(metadata) is dict and set(metadata) == METADATA_KEYS, 'SANITIZATION_METADATA_SCHEMA')
    for name in ('id', 'input_report_id', 'output_report_id'):
        require(type(metadata[name]) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', metadata[name]),
                'SANITIZATION_IDENTIFIER')
    require(len({metadata[name] for name in ('id', 'input_report_id', 'output_report_id')}) == 3,
            'SANITIZATION_DUPLICATE_IDENTIFIERS')
    for name in ('input_sha256', 'output_sha256'):
        require(type(metadata[name]) is str and re.fullmatch(r'[a-f0-9]{64}', metadata[name]), 'SANITIZATION_HASH_SCHEMA')
    for name, limit in (('input_size_bytes', 10 * 1024**2), ('output_size_bytes', MAX_COPY_BYTES)):
        require(type(metadata[name]) is int and 0 < metadata[name] <= limit, 'SANITIZATION_SIZE_SCHEMA')
    require(metadata['profile'] == 'html-text-v1' and metadata['transformation_status'] == 'SANITIZED'
            and metadata['delivery_status'] == 'ALLOWED' and metadata['reason'] == 'COPY_PASSED_CHECKS',
            'SANITIZATION_DECISION')
    require(type(metadata['created_at']) is str, 'SANITIZATION_TIME_SCHEMA')
    try:
        created = datetime.fromisoformat(metadata['created_at'])
        require(created.tzinfo is not None, 'SANITIZATION_TIME_SCHEMA')
    except ValueError:
        raise InvariantError('SANITIZATION_TIME_SCHEMA') from None
    require(type(metadata['input_filename']) is str and re.fullmatch(r'notes-[1-9][0-9]*\.html', metadata['input_filename']),
            'SANITIZATION_FILENAME')
    require(metadata['output_filename'] == metadata['input_filename'][:-5] + '.sanitized.txt', 'SANITIZATION_FILENAME')
    require(type(metadata['omitted_counts']) is dict and set(metadata['omitted_counts']) == COUNT_KEYS
            and all(type(value) is int and value == 0 for value in metadata['omitted_counts'].values()),
            'SANITIZATION_OMISSION_COUNTS')
    return metadata


def validate_delivery(response, source, expected_output, filename):
    require(type(response) is dict and set(response) == METADATA_KEYS | {'delivery'}, 'SANITIZATION_RESPONSE_SCHEMA')
    metadata = validate_metadata({key: response[key] for key in METADATA_KEYS})
    require(metadata['input_filename'] == filename and metadata['input_sha256'] == hashlib.sha256(source).hexdigest()
            and metadata['input_size_bytes'] == len(source), 'SANITIZATION_INPUT_CHANGED')
    delivery = response['delivery']
    require(type(delivery) is dict and set(delivery) == {'encoding', 'media_type', 'data_base64'}
            and delivery['encoding'] == 'base64' and delivery['media_type'] == 'text/plain;charset=utf-8',
            'SANITIZATION_DELIVERY_SCHEMA')
    value = delivery['data_base64']
    require(type(value) is str and 0 < len(value) <= 4 * ((MAX_COPY_BYTES + 2) // 3), 'SANITIZATION_BASE64_SIZE')
    try:
        output = base64.b64decode(value, validate=True)
        output.decode('utf-8', errors='strict')
    except (ValueError, UnicodeError):
        raise InvariantError('SANITIZATION_ENCODING') from None
    require(base64.b64encode(output).decode('ascii') == value, 'SANITIZATION_BASE64_CANONICAL')
    require(output == expected_output and metadata['output_size_bytes'] == len(output)
            and metadata['output_sha256'] == hashlib.sha256(output).hexdigest(), 'SANITIZATION_OUTPUT_CHANGED')
    return metadata, output


def validate_page(rows, ledger, expected_ids):
    require(type(rows) is list and len(rows) == len(expected_ids), 'SANITIZATION_PAGE_SIZE', len(expected_ids), len(rows) if isinstance(rows, list) else None)
    actual_ids = []
    for row in rows:
        validate_metadata(row)
        identifier = row['id']
        require(identifier in ledger, 'SANITIZATION_UNKNOWN_OPERATION')
        require(row == ledger[identifier] and metadata_digest(row) == metadata_digest(ledger[identifier]),
                'SANITIZATION_HISTORY_CHANGED')
        actual_ids.append(identifier)
    require(actual_ids == expected_ids and len(set(actual_ids)) == len(actual_ids), 'SANITIZATION_PAGE_ORDER_OR_DUPLICATE')


def paged_connection_class(original):
    """Permit only the metadata pagination query on the already-proven socket.

    The installed public transport intentionally accepts plain CLI routes only.
    This QA adapter retains its no-reconnect socket, nonce proof, deadline and
    strict response reader. No product transport or endpoint is changed.
    """
    class PagedConnection(original):
        def request(self, method, route, payload=None, content_type='application/json'):
            if '?' not in route:
                return super().request(method, route, payload, content_type)
            require(method == 'GET' and payload is None and re.fullmatch(
                r'/api/sanitizations\?limit=10&offset=[0-9]{1,6}', route), 'SANITIZATION_QUERY_ROUTE')
            require(self._socket is not None and self._http.sock is self._socket and not self._used,
                    'SANITIZATION_CONNECTION_STATE')
            self._used = True
            try:
                self._remaining()
                self._http.request('GET', route, headers={'Authorization': 'Bearer ' + self._token,
                                                         'Accept': 'application/json'})
                return self._read(self._http.getresponse(), 8 * 1024**2)
            except (OSError, ValueError, http.client.HTTPException):
                raise InvariantError('SANITIZATION_PAGE_TRANSPORT_FAILED') from None
            finally:
                self.close()
    return PagedConnection


class FeatureSoak(baseline.Soak):
    def __init__(self, args):
        self.sanitization_ledger = {}
        self._full_history = False
        self._restart_history = False
        super().__init__(args)
        self.Connection = paged_connection_class(self.Connection)
        self.sanitization_log = (self.root / 'sanitizations.jsonl').open('ab', buffering=0)

    def document(self):
        result = super().document()
        result.update(harness_profile='html-copies-v1', baseline_harness_sha256=BASELINE_SHA256,
                      expected_sanitizations=len(self.sanitization_ledger), sanitization_page_size=PAGE_SIZE)
        return result

    def start_backend(self):
        super().start_backend()
        self._full_history = True
        self._restart_history = self.counts['backend_starts'] > 1

    def upload_cases(self, cycle):
        super().upload_cases(cycle)
        self.sanitize_case(cycle)

    def sanitize_case(self, cycle):
        require(len(self.sanitization_ledger) < MAX_OPERATIONS, 'SANITIZATION_LEDGER_LIMIT')
        source, expected_output, filename = fixture(cycle)
        payload, content_type = self.multipart(source, filename)
        response = self.request('POST', '/api/sanitizations/html', raw=payload, content_type=content_type,
                                label='sanitize_html')
        metadata, output = validate_delivery(response, source, expected_output, filename)
        require(metadata['id'] not in self.sanitization_ledger, 'SANITIZATION_DUPLICATE_OPERATION')
        for key, content, origin in (('input_report_id', source, 'sanitization_input'),
                                     ('output_report_id', output, 'sanitization_output')):
            report = self.request('GET', '/api/scans/' + metadata[key], label=origin + '_report')
            self.remember(report, content, 'VALID', origin)
        saved = self.request('GET', '/api/sanitizations/' + metadata['id'], label='sanitize_saved_metadata')
        validate_metadata(saved)
        require(saved == metadata, 'SANITIZATION_SAVED_METADATA_CHANGED')
        with self.lock:
            self.sanitization_ledger[metadata['id']] = metadata
            self.sanitization_log.write(baseline.encoded({'at': baseline.now(), 'operation_id': metadata['id'],
                'input_report_id': metadata['input_report_id'], 'output_report_id': metadata['output_report_id'],
                'input_sha256': metadata['input_sha256'], 'output_sha256': metadata['output_sha256'],
                'input_size_bytes': len(source), 'output_size_bytes': len(output),
                'metadata_sha256': metadata_digest(metadata)}) + b'\n')
        self.increment('sanitizations_completed')

    def check_sanitizations(self):
        identifiers = sorted(self.sanitization_ledger,
            key=lambda identifier: (self.sanitization_ledger[identifier]['created_at'], identifier), reverse=True)
        for offset in range(0, len(identifiers) + 1, PAGE_SIZE):
            rows = self.request('GET', '/api/sanitizations?limit=10&offset=' + str(offset), label='sanitize_registry_page')
            validate_page(rows, self.sanitization_ledger, identifiers[offset:offset + PAGE_SIZE])
            self.increment('sanitization_pages_checked')
        if self._full_history:
            for identifier in identifiers:
                metadata = self.sanitization_ledger[identifier]
                saved = self.request('GET', '/api/sanitizations/' + identifier, label='sanitize_history_metadata')
                validate_metadata(saved)
                require(saved == metadata, 'SANITIZATION_RESTART_METADATA_CHANGED')
                for key in ('input_report_id', 'output_report_id'):
                    report_id = metadata[key]
                    known = self.ledger[report_id]
                    report = self.request('GET', '/api/scans/' + report_id, label='sanitize_history_report')
                    require(self.verified_summary(report, known['sha256'], known['size_bytes']) == known,
                            'SANITIZATION_RESTART_REPORT_CHANGED')
                    self.increment('sanitization_history_reports_checked')
            if self._restart_history:
                self.increment('sanitization_restart_checks')
            self._full_history = self._restart_history = False
        self.increment('sanitization_registry_checks')

    def check_registry(self):
        old_deadline = self.cycle_deadline
        if old_deadline is None:
            self.cycle_deadline = time.monotonic() + baseline.MAX_CYCLE_SECONDS
        try:
            super().check_registry()
            self.check_sanitizations()
        finally:
            self.cycle_deadline = old_deadline

    def run(self):
        try:
            return super().run()
        finally:
            self.sanitization_log.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--python', required=True, type=Path)
    parser.add_argument('--data-root', required=True, type=Path)
    parser.add_argument('--duration', type=float, default=3600)
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--port', type=int)
    parser.add_argument('--restart-every', type=int, default=10)
    parser.add_argument('--selected-runtime', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if (not math.isfinite(args.duration) or not 1 <= args.duration <= 86400
            or not math.isfinite(args.interval) or not .1 <= args.interval <= 3600
            or not 0 <= args.restart_every <= 10000 or args.port is not None and not 1 <= args.port <= 65535):
        parser.error('Invalid duration, interval, restart count or port')
    args.python = Path(os.path.abspath(args.python.expanduser()))
    if not args.python.is_file() or not os.access(args.python, os.X_OK):
        parser.error('The requested Python executable is unavailable')
    if not args.selected_runtime:
        os.execv(args.python, [str(args.python), '-I', str(Path(__file__).resolve()),
                              *sys.argv[1:], '--selected-runtime'])
    if not sys.flags.isolated:
        parser.error('The harness requires the selected Python in isolated mode')
    try:
        runner = FeatureSoak(args)
    except Exception as error:
        print(json.dumps({'status': 'FAILED', 'code': 'HARNESS_SETUP_FAILED', 'type': type(error).__name__}), file=sys.stderr)
        return 2
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: runner.stop_requested.set())
    code = runner.run()
    print(json.dumps({'status': runner.status, 'report': str(runner.root / 'report.json'),
        'cycles': runner.counts['cycles_completed'], 'reports': len(runner.ledger),
        'sanitizations': len(runner.sanitization_ledger), 'failures': len(runner.failures)}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
