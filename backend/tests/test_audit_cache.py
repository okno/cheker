"""Security regressions for reuse of an unchanged, previously verified audit."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrity_guard.core import ConflictError, GuardStore


@pytest.fixture
def store(tmp_path):
    value = GuardStore(tmp_path / 'state')
    for index in range(8):
        value.append_audit('TEST_EVENT', None, {'index': index})
    assert value.verify_audit()['valid']
    yield value
    value.close()


def corrupt_first(connection):
    row = connection.execute('SELECT document FROM audit WHERE sequence=1').fetchone()
    event = json.loads(row[0])
    event['details']['index'] = 'tampered'
    connection.execute('UPDATE audit SET document=? WHERE sequence=1', (json.dumps(event),))


def signature_spy(store, monkeypatch):
    spy = Mock(wraps=store._check_signature)
    monkeypatch.setattr(store, '_check_signature', spy)
    return spy


def test_fast_hit_uses_existing_proof_but_explicit_verification_checks_every_signature(store, monkeypatch):
    spy = signature_spy(store, monkeypatch)
    first = store.verify_audit(fast=True)
    assert first['valid'] and first['checked'] == 8
    assert spy.call_count == 0
    assert store.verify_audit() == first
    assert spy.call_count == 9  # Eight events and the signed head.
    spy.reset_mock()
    assert store.verify_audit(fast=True) == first
    assert spy.call_count == 0


def test_caller_cannot_mutate_cached_result(store):
    result = store.verify_audit(fast=True)
    result.update(valid=False, checked=0, head_hash='tampered')
    again = store.verify_audit(fast=True)
    assert again['valid'] is True and again['checked'] == 8
    assert again['head_hash'] != 'tampered'


@pytest.mark.parametrize('commit', [False, True])
def test_same_connection_tamper_invalidates_pending_and_committed_cache(store, commit):
    corrupt_first(store._db)
    if commit:
        store._db.commit()
    assert not store.verify_audit(fast=True)['valid']
    assert store._audit_cache is None
    with pytest.raises(ConflictError):
        store.append_audit('MUST_NOT_APPEND', None, {})
    assert store._db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 8


def test_external_connection_tamper_invalidates_cache_even_if_mtime_restored(store):
    paths = [store.db_path, Path(str(store.db_path) + '-wal')]
    timestamps = {path: path.stat() for path in paths if path.exists()}
    own_changes = store._db.total_changes
    with sqlite3.connect(store.db_path) as external:
        corrupt_first(external)
    for path, before in timestamps.items():
        if path.exists():
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert store._db.total_changes == own_changes
    assert not store.verify_audit(fast=True)['valid']
    with pytest.raises(ConflictError):
        store.append_audit('MUST_NOT_APPEND', None, {})


def test_external_connection_counter_cannot_be_hidden_by_mocked_file_metadata(store, monkeypatch):
    identities = {str(path): store._audit_file_identity(path, optional=True)
                  for path in [store.db_path, Path(str(store.db_path) + '-wal')]}
    monkeypatch.setattr(store, '_audit_file_identity', lambda path, **kw: identities[str(path)])
    with sqlite3.connect(store.db_path) as external:
        corrupt_first(external)
    assert not store.verify_audit(fast=True)['valid']


def test_unrelated_external_write_forces_reverification_instead_of_guessing_audit_unchanged(store, monkeypatch):
    spy = signature_spy(store, monkeypatch)
    with sqlite3.connect(store.db_path) as external:
        external.execute("INSERT INTO settings(key,value) VALUES ('unrelated','test')")
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 9


@pytest.mark.parametrize('tamper', ['malformed', 'truncated_log', 'oversized', 'signature'])
def test_checkpoint_or_tail_tamper_never_reuses_valid_result(store, tamper):
    if tamper == 'truncated_log':
        store._db.execute('DELETE FROM audit WHERE sequence=8'); store._db.commit()
    elif tamper == 'oversized':
        store._checkpoint_path.write_bytes(b' ' * 4097)
    elif tamper == 'signature':
        value = json.loads(store._checkpoint_path.read_bytes())
        value['signature'] = 'A' * len(value['signature'])
        store._checkpoint_path.write_text(json.dumps(value))
    else:
        store._checkpoint_path.write_text('{}')
    assert not store.verify_audit(fast=True)['valid']
    assert store._audit_cache is None


def test_checkpoint_restoration_after_detected_tamper_requires_full_verification(store, monkeypatch):
    original = store._checkpoint_path.read_bytes()
    store._checkpoint_path.write_bytes(b'{}')
    assert not store.verify_audit(fast=True)['valid']
    spy = signature_spy(store, monkeypatch)
    store._checkpoint_path.write_bytes(original)
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 9


def test_rolled_back_transaction_does_not_publish_uncommitted_proof(store, monkeypatch):
    corrupt_first(store._db)
    assert not store.verify_audit(fast=True)['valid']
    store._db.rollback()
    spy = signature_spy(store, monkeypatch)
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 9


def test_mutation_rolled_back_without_intermediate_check_still_invalidates_cache(store, monkeypatch):
    corrupt_first(store._db)
    store._db.rollback()
    spy = signature_spy(store, monkeypatch)
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 9


def test_external_write_during_full_verification_cannot_seed_stale_proof(store, monkeypatch):
    original = store._check_signature
    changed = False
    def verify_then_mutate(value, signature):
        nonlocal changed
        valid = original(value, signature)
        if not changed:
            changed = True
            with sqlite3.connect(store.db_path) as external:
                corrupt_first(external)
        return valid
    monkeypatch.setattr(store, '_check_signature', verify_then_mutate)
    assert not store.verify_audit()['valid']
    assert store._audit_cache is None
    assert not store.verify_audit(fast=True)['valid']


def test_valid_uncommitted_write_also_cannot_publish_cache(store, monkeypatch):
    store._db.execute("INSERT INTO settings(key,value) VALUES ('uncommitted','test')")
    assert store.verify_audit(fast=True)['valid']
    assert store._audit_cache is None
    store._db.rollback()
    spy = signature_spy(store, monkeypatch)
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 9


def test_normal_append_advances_verified_head_after_durable_checkpoint(store, monkeypatch):
    spy = signature_spy(store, monkeypatch)
    for index in range(5):
        event = store.append_audit('NORMAL_APPEND', None, {'index': index})
        result = store.verify_audit(fast=True)
        assert result['valid'] and result['checked'] == index + 9
        assert result['head_hash'] == event['hash']
    assert spy.call_count == 0
    assert store.verify_audit()['checked'] == 13
    assert spy.call_count == 14


def test_checkpoint_write_failure_clears_cache_and_blocks_followup(store, monkeypatch):
    def fail(*args):
        raise OSError('fixture checkpoint failure')
    monkeypatch.setattr(store, '_write_checkpoint', fail)
    with pytest.raises(OSError):
        store.append_audit('COMMITTED_WITHOUT_CHECKPOINT', None, {})
    assert store._audit_cache is None
    assert not store.verify_audit(fast=True)['valid']
    assert store._db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 9


@pytest.mark.parametrize('external', [False, True])
def test_write_between_commit_and_checkpoint_cannot_be_promoted_as_valid(store, monkeypatch, external):
    original = store._write_checkpoint
    def tamper_then_write(*args):
        if external:
            with sqlite3.connect(store.db_path) as connection:
                corrupt_first(connection)
        else:
            corrupt_first(store._db); store._db.commit()
        return original(*args)
    monkeypatch.setattr(store, '_write_checkpoint', tamper_then_write)
    with pytest.raises(ConflictError):
        store.append_audit('RACED_APPEND', None, {})
    assert store._audit_cache is None
    assert not store.verify_audit(fast=True)['valid']


def test_sqlite_trigger_cannot_change_verified_prefix_during_append(store):
    store._db.execute("""CREATE TRIGGER corrupt_audit AFTER INSERT ON audit
        BEGIN UPDATE audit SET document='{}' WHERE sequence=1; END""")
    store._db.commit()
    assert not store.verify_audit(fast=True)['valid']
    with pytest.raises(ValueError, match='schema'):
        store.append_audit('TRIGGERED_APPEND', None, {})
    assert store._db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 8


def test_view_with_single_change_trigger_cannot_forge_a_successful_append(store):
    store._db.executescript("""
        ALTER TABLE audit RENAME TO audit_original;
        CREATE TABLE sink (sequence INTEGER, document TEXT);
        CREATE VIEW audit AS SELECT sequence,document FROM audit_original;
        CREATE TRIGGER hide_new_event INSTEAD OF INSERT ON audit BEGIN
            INSERT INTO sink(sequence,document) VALUES (NEW.sequence,NEW.document);
        END;
    """)
    assert not store.verify_audit(fast=True)['valid']
    with pytest.raises(ValueError, match='schema'):
        store.append_audit('HIDDEN_SUFFIX', None, {})
    assert store._db.execute('SELECT COUNT(*) FROM sink').fetchone()[0] == 0


@pytest.mark.parametrize('schema', ['view', 'trigger'])
@pytest.mark.parametrize('restore_version', [False, True])
def test_temporary_schema_changes_invalidate_even_without_total_changes(store, schema, restore_version):
    before = store._db.total_changes
    version = store._db.execute('PRAGMA temp.schema_version').fetchone()[0]
    if schema == 'view':
        store._db.execute('CREATE TEMP VIEW audit AS SELECT * FROM main.audit WHERE sequence<8')
    else:
        store._db.execute("""CREATE TEMP TRIGGER hide_event BEFORE INSERT ON main.audit
            BEGIN SELECT RAISE(IGNORE); END""")
    if restore_version:
        store._db.execute(f'PRAGMA temp.schema_version={version}')
    assert store._db.total_changes == before
    assert not store.verify_audit(fast=True)['valid']
    with pytest.raises(ValueError, match='schema'):
        store.append_audit('MUST_NOT_APPEND', None, {})


def test_changed_batch_is_verified_once_after_commit_and_checkpoint(store, monkeypatch):
    with store.lock, store._atomic_updates():
        store.append_audit('BATCH_A', None, {})
        store.append_audit('BATCH_B', None, {})
    assert store._audit_cache is None
    spy = signature_spy(store, monkeypatch)
    assert store.verify_audit(fast=True)['checked'] == 10
    assert spy.call_count == 11
    spy.reset_mock()
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 0


def test_mixed_batch_cannot_hide_prefix_tampering(store):
    with store.lock, store._atomic_updates():
        corrupt_first(store._db)
        store.append_audit('BATCH_SUFFIX', None, {})
    assert store._audit_cache is None
    assert not store.verify_audit(fast=True)['valid']


def test_failed_batch_rolls_back_rows_and_clears_proof(store, monkeypatch):
    before = store._checkpoint_path.read_bytes()
    with pytest.raises(RuntimeError, match='cancel fixture'):
        with store.lock, store._atomic_updates():
            store.append_audit('ROLLED_BACK', None, {})
            raise RuntimeError('cancel fixture')
    assert store._audit_cache is None
    assert store._checkpoint_path.read_bytes() == before
    spy = signature_spy(store, monkeypatch)
    assert store.verify_audit(fast=True)['checked'] == 8
    assert spy.call_count == 9


def test_unchanged_batch_preserves_proof(store, monkeypatch):
    spy = signature_spy(store, monkeypatch)
    with store.lock, store._atomic_updates():
        assert store._db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 8
    assert store.verify_audit(fast=True)['valid']
    assert spy.call_count == 0


def test_reopening_store_requires_new_full_verification(store, monkeypatch):
    directory = store.data_dir
    store.close()
    reopened = GuardStore(directory)
    try:
        spy = signature_spy(reopened, monkeypatch)
        assert reopened._audit_cache is None
        assert reopened.verify_audit(fast=True)['checked'] == 8
        assert spy.call_count == 9
    finally:
        reopened.close()


def test_loaded_verification_key_change_invalidates_cache(store):
    store._key = Ed25519PrivateKey.generate()
    assert not store.verify_audit(fast=True)['valid']


def test_database_file_replacement_cannot_reuse_open_connection_proof(store):
    if os.name == 'nt':
        pytest.skip('Windows does not allow replacing an open SQLite database')
    replacement = store.data_dir / 'replacement.sqlite3'
    replacement.write_bytes(store.db_path.read_bytes())
    os.replace(replacement, store.db_path)
    result = store.verify_audit(fast=True)
    assert not result['valid']
    assert 'replaced' in result['error']


def test_cache_evidence_read_failure_fails_closed_without_leaving_a_writer_transaction(store, monkeypatch):
    def fail():
        raise OSError('fixture stat failure')
    monkeypatch.setattr(store, '_audit_evidence', fail)
    assert not store.verify_audit(fast=True)['valid']
    assert store._audit_cache is None
    with pytest.raises(OSError):
        store.append_audit('MUST_NOT_APPEND', None, {})
    assert store._db.in_transaction is False


@pytest.mark.parametrize('name', ['Audit', 'AuDiT', 'AUDIT'])
def test_schema_validation_matches_sqlite_identifier_casing(store, name):
    store._db.execute(f'CREATE TEMP TABLE "{name}" (sequence INTEGER PRIMARY KEY, document TEXT NOT NULL)')
    store._db.commit()
    with pytest.raises(ValueError, match='schema'):
        store._assert_audit_schema()
