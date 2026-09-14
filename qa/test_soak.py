"""Registry pagination regressions for the standalone soak harness (stdlib only).

Run with: python3 -m unittest discover -s qa -p test_soak.py -v
"""
import ast
import hashlib
from pathlib import Path
import unittest

from soak import InvariantError, REGISTRY_PAGE_SIZE, validate_registry_page


def registry(count):
    rows, ledger = [], {}
    for index in range(count):
        identifier = f"00000000-0000-4000-8000-{index:012d}"
        digest = hashlib.sha256(str(index).encode()).hexdigest()
        summary = {"report_id": identifier, "sha256": digest, "size_bytes": index, "verdict": "VALID"}
        ledger[identifier] = summary
        rows.append({"id": identifier, **summary})
    return list(reversed(rows)), ledger


def verified_summary(report, digest, size):
    if report["sha256"] != digest or report["size_bytes"] != size:
        raise InvariantError("REPORT_BYTES_CHANGED")
    return {key: value for key, value in report.items() if key != "id"}


class RegistryPageTests(unittest.TestCase):
    def test_default_page_contract_matches_api(self):
        # Inspect source only: do not import or instantiate the production API.
        source = Path(__file__).resolve().parents[1] / "backend/integrity_guard/api.py"
        tree = ast.parse(source.read_text())
        endpoint = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "scans")
        defaults = dict(zip([arg.arg for arg in endpoint.args.args][-len(endpoint.args.defaults):], endpoint.args.defaults))
        self.assertEqual(ast.literal_eval(defaults["limit"].args[0]), REGISTRY_PAGE_SIZE)

    def test_all_boundary_sizes_through_multiple_pages(self):
        for total in (0, 1, 49, 50, 51, 56, 99, 100, 101, 156, 250):
            with self.subTest(total=total):
                rows, ledger = registry(total)
                # API contract: the unparameterized endpoint returns up to 100.
                validate_registry_page(rows[:100], ledger, verified_summary)

    def test_old_fifty_record_assumption_cannot_mask_missing_results(self):
        rows, ledger = registry(56)
        with self.assertRaises(InvariantError) as caught:
            validate_registry_page(rows[:50], ledger, verified_summary)
        self.assertEqual(caught.exception.detail, {"code": "REGISTRY_PAGE_SIZE", "expected": 56, "actual": 50})

    def test_truncated_second_page_boundary_is_rejected(self):
        rows, ledger = registry(156)
        with self.assertRaises(InvariantError) as caught:
            validate_registry_page(rows[:99], ledger, verified_summary)
        self.assertEqual(caught.exception.detail["expected"], 100)
        self.assertEqual(caught.exception.detail["actual"], 99)

    def test_duplicates_unknown_ids_and_changed_hashes_are_rejected(self):
        for kind in ("duplicate", "unknown", "changed"):
            with self.subTest(kind=kind):
                rows, ledger = registry(156)
                page = rows[:100]
                if kind == "duplicate":
                    page[-1] = page[0]
                elif kind == "unknown":
                    page[-1] = {**page[-1], "id": "00000000-0000-4000-8000-999999999999"}
                else:
                    page[-1] = {**page[-1], "sha256": "0" * 64}
                with self.assertRaises(InvariantError):
                    validate_registry_page(page, ledger, verified_summary)


if __name__ == "__main__":
    unittest.main()
