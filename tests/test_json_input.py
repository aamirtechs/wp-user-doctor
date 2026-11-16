"""JSON exports use the same auditing rules as CSV exports."""

import csv
import datetime
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import wp_user_doctor as wud

AS_OF = datetime.date(2026, 11, 11)


class TestJsonInput(unittest.TestCase):
    def analyze(self, records):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            path.write_text(json.dumps(records), encoding="utf-8-sig")
            return wud.analyze_file(path, as_of=AS_OF, input_format="json")

    def test_samples_match_csv(self):
        for name in ["users.csv", "clean.csv", "warnings-only.csv"]:
            with self.subTest(sample=name):
                path = ROOT / "examples" / name
                with path.open(newline="", encoding="utf-8") as handle:
                    reader = csv.reader(handle)
                    header = next(reader)
                    records = [dict(zip(header, row)) for row in reader]
                expected = wud.analyze_file(path, as_of=AS_OF)
                self.assertEqual(self.analyze(records), expected)
                if name == "users.csv":
                    self.assertEqual(expected["summary"]["findings"], 16)

    def test_aliases_key_order_numeric_ids_and_null_cells(self):
        report = self.analyze([
            {"ID": 1, " Login ": "boss", "email": "boss@example.com",
             "roles": "administrator", "last_logged_in": "2026-11-10"},
            {"roles": "subscriber", "last_logged_in": None, "ID": 2,
             "email": "reader@example.com", " Login ": "reader"},
        ])
        self.assertEqual(report["summary"]["users"], 2)
        self.assertEqual([f["rule"] for f in report["findings"]],
                         ["never-logged-in"])

    def test_empty_array(self):
        report = self.analyze([])
        self.assertEqual(report["summary"]["users"], 0)
        self.assertEqual(report["findings"], [])
        self.assertFalse(report["summary"]["last_login_column"])

    def test_non_array_or_non_object_records_are_rejected(self):
        for value in [{}, None, "users", 2, [None],
                      [{"login": "a", "email": "a@example.com",
                        "role": "subscriber"}, "not a user"]]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "JSON"):
                    self.analyze(value)

    def test_nested_field_values_are_rejected(self):
        for value in [["administrator"], {"name": "administrator"}]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "JSON.*role"):
                    self.analyze([{"login": "a", "email": "a@example.com",
                                  "role": value}])

    def test_different_fields_are_reported_and_skipped(self):
        report = self.analyze([
            {"login": "a", "email": "a@example.com", "role": "subscriber"},
            {"login": "b", "email": "b@example.com", "other": "subscriber"},
        ])
        self.assertEqual(report["summary"]["users"], 1)
        self.assertEqual([f["rule"] for f in report["findings"]],
                         ["malformed-row"])

    def test_cli_matches_csv_text_json_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            sample = ROOT / "examples" / "users.csv"
            with sample.open(newline="", encoding="utf-8") as handle:
                reader = csv.reader(handle)
                header = next(reader)
                path.write_text(json.dumps([dict(zip(header, row))
                                            for row in reader]),
                                encoding="utf-8")
            for output in [[], ["--json"]]:
                with self.subTest(output=output):
                    options = ["--as-of", "2026-11-11", "--check"] + output
                    command = [sys.executable, str(ROOT / "wp_user_doctor.py")]
                    csv_result = subprocess.run(command + [str(sample)] + options,
                                                capture_output=True, text=True)
                    json_result = subprocess.run(
                        command + [str(path), "--format", "json"] + options,
                        capture_output=True, text=True)
                    self.assertEqual(json_result.returncode, 1, json_result.stderr)
                    self.assertEqual(json_result.stdout, csv_result.stdout)
                    self.assertEqual(json_result.stderr, "")

    def test_invalid_json_reports_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            path.write_text("[{", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "wp_user_doctor.py"),
                 str(path), "--format", "json"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid JSON", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(result.stdout, "")
