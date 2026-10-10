import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
import tool

ROOT = Path(__file__).parent

def fixture(name="good"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())

class CLITests(unittest.TestCase):
    def run_tool(self, raw):
        return subprocess.run([sys.executable, str(ROOT / "tool.py")], input=raw, capture_output=True, text=True)

    def test_cli_fixture_exit_codes(self):
        for name, code in [("good", 0), ("bad", 1)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--input", str(ROOT / "examples" / (name + ".json"))], capture_output=True, text=True)
            self.assertEqual(run.returncode, code, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["ok"], code == 0)
            self.assertEqual(run.stderr, "")

    def test_cli_argument_errors_are_json_and_redacted(self):
        secret = "PRIVATE_ARGUMENT_MARKER"
        for arguments in [("--unknown", secret), ("--input",),
                          ("--pretty=" + secret,), (secret,)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), *arguments],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stderr, "")
            self.assertNotIn(secret, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_cli_help_remains_text_and_success(self):
        run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--help"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stderr, "")
        self.assertIn("--input", run.stdout)

    def test_large_json_integer_is_safe_error(self):
        run=self.run_tool('{"number":'+'9'*5000+'}')
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')
        self.assertEqual(json.loads(run.stdout)['error']['code'],'invalid_input')

    def test_nonregular_input_file(self):
        run=subprocess.run([sys.executable,str(ROOT/'tool.py'),'--input',str(ROOT)],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')

    def test_bad_json(self):
        for raw in ['{', '{"x":1,"x":2}', '[]', '{"x":NaN}', '"' + 'x' * (tool.MAX_BYTES + 1) + '"']:
            run = self.run_tool(raw)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_unknown_field_and_boolean_number(self):
        obj = fixture(); obj["unrecognized"] = 1
        with self.assertRaises(tool.InputError): tool.audit(obj)

    def test_output_is_deterministic(self):
        raw=json.dumps(fixture())
        self.assertEqual(self.run_tool(raw).stdout, self.run_tool(raw).stdout)

class CacheTests(unittest.TestCase):
    def test_age_formula(self):
        out=tool.audit(fixture())
        self.assertEqual(out["current_age_seconds"], 35)
        self.assertEqual(out["remaining_fresh_seconds"], 25)
        self.assertFalse(out["reuse_authorized"])
    def test_exact_expiry(self):
        d=fixture(); d["cache_control"]=["max-age=35"]
        self.assertFalse(tool.audit(d)["fresh_by_max_age"])
    def test_duplicate_and_missing(self):
        for lines in [["max-age=10", "MAX-AGE=20"], ["public"], ['max-age="abc"']]:
            d=fixture(); d["cache_control"]=lines
            self.assertFalse(tool.audit(d)["ok"])
    def test_quoted_comma_and_unknown(self):
        d=fixture(); d["cache_control"]=['max-age="60", note="a,b", public']
        self.assertTrue(tool.audit(d)["ok"])
        self.assertIn("note", tool.audit(d)["unmodeled_directives"])
    def test_policy_not_reuse(self):
        d=fixture(); d["cache_control"]=["max-age=60, no-store"]
        out=tool.audit(d); self.assertTrue(out["fresh_by_max_age"]); self.assertFalse(out["ok"])
    def test_future_date(self):
        d=fixture(); d["date"]="Tue, 02 Jan 2024 00:00:00 GMT"
        self.assertEqual(tool.audit(d)["apparent_age_seconds"],0)
        self.assertFalse(tool.audit(d)["ok"])
    def test_bad_date_clock_age(self):
        for key,value in [("date","Tue, 01 Jan 2024 00:00:00 GMT"),("age","-1"),("age","١"),("now",0),("request_time",True)]:
            d=fixture(); d[key]=value
            with self.assertRaises(tool.InputError): tool.audit(d)
    def test_bad_directive_quotes_controls(self):
        for value in ['max-age="60', 'max-age=60\r\nX: leak']:
            d=fixture(); d["cache_control"]=[value]
            with self.assertRaises(tool.InputError): tool.audit(d)
    def test_apparent_age_dominates(self):
        d=fixture(); d["date"]="Sun, 31 Dec 2023 23:59:00 GMT"
        self.assertEqual(tool.audit(d)["current_age_seconds"],90)

if __name__ == "__main__": unittest.main()
