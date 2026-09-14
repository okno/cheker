"""Functional contracts for the separate HTML-copy soak; synthetic metadata only."""
import base64
import collections
import copy
import hashlib
import io
import re
from types import SimpleNamespace
import unittest

from soak_features import (COUNT_KEYS, FeatureSoak, InvariantError, PAGE_SIZE, fixture,
                           metadata_digest, paged_connection_class, validate_delivery,
                           validate_metadata, validate_page)


def sample(index=1):
    source, output, filename = fixture(index)
    metadata = {'id': f'00000000-0000-4000-8000-{index * 3:012d}',
        'input_report_id': f'00000000-0000-4000-8000-{index * 3 + 1:012d}',
        'output_report_id': f'00000000-0000-4000-8000-{index * 3 + 2:012d}',
        'created_at': f'2026-09-14T19:00:{index % 60:02d}.000000+00:00', 'profile': 'html-text-v1',
        'transformation_status': 'SANITIZED', 'delivery_status': 'ALLOWED', 'reason': 'COPY_PASSED_CHECKS',
        'input_filename': filename, 'output_filename': filename[:-5] + '.sanitized.txt',
        'input_sha256': hashlib.sha256(source).hexdigest(), 'output_sha256': hashlib.sha256(output).hexdigest(),
        'input_size_bytes': len(source), 'output_size_bytes': len(output),
        'omitted_counts': dict.fromkeys(COUNT_KEYS, 0)}
    response = dict(metadata, delivery={'encoding': 'base64', 'media_type': 'text/plain;charset=utf-8',
                                      'data_base64': base64.b64encode(output).decode('ascii')})
    return metadata, response, source, output, filename


class DeliveryTests(unittest.TestCase):
    def test_exact_unicode_delivery_and_metadata_hash_are_stable(self):
        metadata, response, source, output, filename = sample()
        self.assertEqual(validate_delivery(response, source, output, filename), (metadata, output))
        self.assertGreater(len(output), len(output.decode('utf-8')))
        self.assertEqual(metadata_digest(metadata), metadata_digest(dict(reversed(list(metadata.items())))))

    def test_inconsistent_or_incomplete_delivery_fails_without_source_details(self):
        for field, value in (('delivery_status', 'DENIED'), ('transformation_status', 'FAILED'),
                             ('input_sha256', '0' * 64), ('output_sha256', '0' * 64),
                             ('output_size_bytes', True), ('output_size_bytes', 1),
                             ('input_filename', 'private-document'), ('omitted_counts', {})):
            with self.subTest(field=field):
                _, response, source, output, filename = sample()
                response[field] = value
                with self.assertRaises(InvariantError) as caught:
                    validate_delivery(response, source, output, filename)
                self.assertNotIn('Caffè', str(caught.exception.detail))
                self.assertNotIn('private-document', str(caught.exception.detail))
        for value in ('***', 'a' * (400_000), base64.b64encode(b'changed').decode()):
            _, response, source, output, filename = sample()
            response['delivery']['data_base64'] = value
            with self.assertRaises(InvariantError):
                validate_delivery(response, source, output, filename)

    def test_get_metadata_cannot_include_delivery_or_duplicate_report_ids(self):
        metadata, response, *_ = sample()
        with self.assertRaises(InvariantError):
            validate_metadata(response)
        metadata['output_report_id'] = metadata['input_report_id']
        with self.assertRaises(InvariantError):
            validate_metadata(metadata)


class PaginationTests(unittest.TestCase):
    def test_metadata_pages_cover_boundaries_and_empty_tail(self):
        self.assertEqual(PAGE_SIZE, 10)
        for count in (0, 1, 9, 10, 11, 20, 21, 101):
            with self.subTest(count=count):
                ledger = {row['id']: row for row in (sample(index)[0] for index in range(1, count + 1))}
                ids = sorted(ledger, key=lambda key: (ledger[key]['created_at'], key), reverse=True)
                seen = []
                for offset in range(0, count + 1, PAGE_SIZE):
                    expected = ids[offset:offset + PAGE_SIZE]
                    validate_page([ledger[key] for key in expected], ledger, expected)
                    seen.extend(expected)
                self.assertEqual(seen, ids)

    def test_missing_duplicate_unknown_changed_and_leaked_metadata_fail(self):
        ledger = {row['id']: row for row in (sample(index)[0] for index in range(1, 12))}
        ids = sorted(ledger, key=lambda key: (ledger[key]['created_at'], key), reverse=True)[:10]
        for kind in ('missing', 'duplicate', 'unknown', 'changed', 'delivery'):
            with self.subTest(kind=kind):
                rows = [copy.deepcopy(ledger[key]) for key in ids]
                if kind == 'missing': rows.pop()
                elif kind == 'duplicate': rows[-1] = rows[0]
                elif kind == 'unknown': rows[-1] = sample(999)[0]
                elif kind == 'changed': rows[0]['input_sha256'] = '0' * 64
                else: rows[0]['delivery'] = {'data_base64': 'never accepted'}
                with self.assertRaises(InvariantError):
                    validate_page(rows, ledger, ids)


class HistoryTests(unittest.TestCase):
    def runner(self, count=11):
        runner = FeatureSoak.__new__(FeatureSoak)
        runner.sanitization_ledger = {row['id']: row for row in (sample(index)[0] for index in range(1, count + 1))}
        runner.ledger = {}
        runner.counts = collections.Counter()
        runner.increment = lambda key, amount=1: runner.counts.update({key: amount})
        runner._full_history = runner._restart_history = True
        for row in runner.sanitization_ledger.values():
            for prefix in ('input', 'output'):
                identifier = row[prefix + '_report_id']
                runner.ledger[identifier] = {'report_id': identifier, 'sha256': row[prefix + '_sha256'],
                                             'size_bytes': row[prefix + '_size_bytes'], 'verdict': 'VALID'}
        runner.requests = []

        def request(method, route, *, label):
            runner.requests.append(route)
            if '?' in route:
                offset = int(route.split('offset=')[1])
                rows = sorted(runner.sanitization_ledger.values(), key=lambda item: (item['created_at'], item['id']), reverse=True)
                return rows[offset:offset + 10]
            identifier = route.rsplit('/', 1)[1]
            return runner.ledger[identifier] if '/scans/' in route else runner.sanitization_ledger[identifier]

        def verify(report, digest, size):
            if report['sha256'] != digest or report['size_bytes'] != size:
                raise InvariantError('HASH_CHANGED')
            return report

        runner.request = request
        runner.verified_summary = verify
        return runner

    def test_restart_checks_all_eleven_operations_and_twenty_two_reports(self):
        runner = self.runner()
        runner.check_sanitizations()
        self.assertEqual(runner.counts['sanitization_pages_checked'], 2)
        self.assertEqual(runner.counts['sanitization_history_reports_checked'], 22)
        self.assertEqual(runner.counts['sanitization_restart_checks'], 1)
        self.assertFalse(runner._full_history)
        runner.check_sanitizations()
        self.assertEqual(runner.counts['sanitization_history_reports_checked'], 22)
        runner._full_history = runner._restart_history = True
        runner.check_sanitizations()
        self.assertEqual(runner.counts['sanitization_history_reports_checked'], 44)
        self.assertEqual(runner.counts['sanitization_restart_checks'], 2)

    def test_changed_report_stops_at_first_failed_read_without_retry(self):
        runner = self.runner()
        original = runner.request
        bad_routes = []

        def changed(method, route, *, label):
            result = original(method, route, label=label)
            if '/scans/' in route:
                bad_routes.append(route)
                return dict(result, sha256='0' * 64)
            return result

        runner.request = changed
        with self.assertRaises(InvariantError):
            runner.check_sanitizations()
        self.assertEqual(len(bad_routes), 1)
        self.assertEqual(runner.counts['sanitization_restart_checks'], 0)


class TransportTests(unittest.TestCase):
    def connection(self):
        class Base:
            def __init__(self):
                self._socket = object()
                self._used = False
                self._token = 'synthetic-qa-token'
                self.sent = []
                self.closed = False
                self._http = SimpleNamespace(sock=self._socket, request=lambda *a, **k: self.sent.append((a, k)),
                                             getresponse=lambda: object())
            def _remaining(self): pass
            def _read(self, response, limit): return []
            def close(self): self.closed = True
            def request(self, *args): return 'baseline-route'
        return paged_connection_class(Base)()

    def test_only_metadata_pagination_uses_proven_socket(self):
        connection = self.connection()
        self.assertEqual(connection.request('GET', '/api/sanitizations?limit=10&offset=10'), [])
        self.assertEqual(len(connection.sent), 1)
        self.assertTrue(connection.closed)
        self.assertTrue(connection._used)
        self.assertEqual(self.connection().request('GET', '/api/status'), 'baseline-route')

    def test_other_queries_and_changed_socket_send_nothing(self):
        for method, route in (('POST', '/api/sanitizations?limit=10&offset=0'),
                              ('GET', '/api/sanitizations?limit=100&offset=0'),
                              ('GET', '/api/other?limit=10&offset=0')):
            connection = self.connection()
            with self.assertRaises(InvariantError): connection.request(method, route)
            self.assertEqual(connection.sent, [])
        connection = self.connection()
        connection._http.sock = object()
        with self.assertRaises(InvariantError): connection.request('GET', '/api/sanitizations?limit=10&offset=0')
        self.assertEqual(connection.sent, [])


if __name__ == '__main__':
    unittest.main()
