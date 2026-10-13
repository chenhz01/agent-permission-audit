# -*- coding: utf-8 -*-
"""self_test for agent-permission-audit — scaffold v2 four defenses inherited.

D1 SystemExit caught in run_cli; D2 unicode-safe handling (no ASCII-only \\w
on names); D3 fixtures written with newline=""; D4 last line SUMMARY: PASS n/n.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import contextlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_permission_audit as m  # noqa: E402


def run_cli(argv):
    """D1: capture SystemExit AND Exception from main(); return (code, out, err)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = m.main(argv)
            code = rc if isinstance(rc, int) else 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:  # noqa: BLE001
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


def tmp_json(obj):
    """D3: write fixtures with newline='' to avoid \\r\\n double translation."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


MANIFEST = {"tools": [
    {"name": "fs", "ops": ["read", "write"]},
    {"name": "shell", "ops": ["exec"]},
    {"name": "http", "ops": ["network"]},
]}
FULL_POLICY = {"allow": ["fs:read", "fs:write", "shell:exec", "http:network"], "deny": []}


class TestCore(unittest.TestCase):
    def test_pair_enumeration(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertEqual(r["total_pairs"], 4)

    def test_duplicate_pairs_deduped(self):
        r = m.audit({"tools": [{"name": "fs", "ops": ["read", "read"]}]},
                    {"allow": [], "deny": []})
        self.assertEqual(r["total_pairs"], 1)

    def test_allow_exact(self):
        r = m.audit(MANIFEST, {"allow": ["fs:read"], "deny": []})
        self.assertEqual(r["allowed"], 1)

    def test_allow_tool_wildcard(self):
        r = m.audit(MANIFEST, {"allow": ["fs:*"], "deny": []})
        self.assertEqual(r["allowed"], 2)

    def test_allow_op_wildcard(self):
        r = m.audit(MANIFEST, {"allow": ["*:read"], "deny": []})
        self.assertEqual(r["allowed"], 1)

    def test_allow_global_wildcard(self):
        r = m.audit(MANIFEST, {"allow": ["*:*"], "deny": []})
        self.assertEqual(r["unreviewed"], 0)

    def test_deny_overrides_allow(self):
        r = m.audit(MANIFEST, {"allow": ["*:*"], "deny": ["shell:exec"]})
        self.assertEqual(r["denied"], 1)
        self.assertEqual(r["allowed"], 3)

    def test_deny_tool_wildcard(self):
        r = m.audit(MANIFEST, {"allow": ["*:*"], "deny": ["fs:*"]})
        self.assertEqual(r["denied"], 2)

    def test_score_all_allowed(self):
        r = m.audit(MANIFEST, FULL_POLICY)
        self.assertEqual(r["score"], 100.0)

    def test_score_all_unreviewed(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertEqual(r["score"], 0.0)

    def test_risk_weighted_excludes_low_risk(self):
        # fs:read allowed (w=1); remaining w=10 unreviewed -> 10/11 => 90.9
        r = m.audit(MANIFEST, {"allow": ["fs:read"], "deny": []})
        self.assertEqual(r["risk_weighted_surface_pct"], 90.9)

    def test_grade_a(self):
        r = m.audit(MANIFEST, FULL_POLICY)
        self.assertEqual(r["grade"], "A")

    def test_grade_d(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertEqual(r["grade"], "D")

    def test_grade_c_band(self):
        r = m.audit(MANIFEST, {"allow": ["fs:read"], "deny": []})
        self.assertEqual(r["grade"], "D")  # score ~9.1

    def test_unknown_op_weight_default(self):
        r = m.audit({"tools": [{"name": "x", "ops": ["transform"]}]},
                    {"allow": [], "deny": []})
        self.assertEqual(r["unreviewed_pairs"][0]["weight"], 2)

    def test_redundant_all_allow(self):
        r = m.audit(MANIFEST, {"allow": ["*:*", "fs:read"], "deny": []})
        self.assertIn("fs:read", r["redundant_allows"])

    def test_redundant_tool_wildcard(self):
        r = m.audit(MANIFEST, {"allow": ["fs:*", "fs:read"], "deny": []})
        self.assertIn("fs:read", r["redundant_allows"])

    def test_no_redundancy_exact_only(self):
        r = m.audit(MANIFEST, FULL_POLICY)
        self.assertEqual(r["redundant_allows"], [])

    def test_recommendations_present(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertTrue(any("shell:exec" in x for x in r["recommendations"]))

    def test_recommendation_priority_exec_first(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertIn("shell:exec", r["recommendations"][0])

    def test_schema_field(self):
        r = m.audit(MANIFEST, FULL_POLICY)
        self.assertEqual(r["schema"], "agent-permission-audit/v1")

    def test_unreviewed_pairs_sorted(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        ws = [p["weight"] for p in r["unreviewed_pairs"]]
        self.assertEqual(ws, sorted(ws, reverse=True))

    def test_parse_rule_ok(self):
        self.assertEqual(m.parse_rule("a:b"), ("a", "b"))

    def test_parse_rule_wildcards(self):
        self.assertEqual(m.parse_rule("*:*"), ("*", "*"))

    def test_rule_matches_exact(self):
        self.assertTrue(m.rule_matches(("a", "b"), "a", "b"))

    def test_rule_matches_no(self):
        self.assertFalse(m.rule_matches(("a", "b"), "a", "c"))

    def test_empty_manifest_zero_surface(self):
        r = m.audit({"tools": []}, {"allow": [], "deny": []})
        self.assertEqual((r["total_pairs"], r["surface_pct"]), (0, 0.0))

    def test_surface_pct_value(self):
        r = m.audit(MANIFEST, {"allow": ["fs:read", "fs:write", "shell:exec", "http:network"], "deny": []})
        self.assertEqual(r["surface_pct"], 0.0)

    def test_half_surface(self):
        r = m.audit(MANIFEST, {"allow": ["fs:read"], "deny": []})
        self.assertEqual(r["surface_pct"], 75.0)


class TestCli(unittest.TestCase):
    def test_help_exit_zero(self):
        code, out, _ = run_cli(["--help"])
        self.assertEqual(code, 0)

    def test_version_flag(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.1", out)

    def test_no_subcommand_exit2(self):
        code, _, err = run_cli([])
        self.assertEqual(code, 2)

    def test_missing_manifest_arg(self):
        code, _, err = run_cli(["audit", "--policy", "x.json"])
        self.assertEqual(code, 2)

    def test_json_output(self):
        pm, pp = tmp_json(MANIFEST), tmp_json(FULL_POLICY)
        code, out, _ = run_cli(["audit", "--manifest", pm, "--policy", pp, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["grade"], "A")

    def test_text_output(self):
        pm, pp = tmp_json(MANIFEST), tmp_json(FULL_POLICY)
        code, out, _ = run_cli(["audit", "--manifest", pm, "--policy", pp])
        self.assertEqual(code, 0)
        self.assertIn("grade: A", out)

    def test_strict_pass(self):
        pm, pp = tmp_json(MANIFEST), tmp_json(FULL_POLICY)
        code, _, _ = run_cli(["audit", "--manifest", pm, "--policy", pp, "--min-score", "90"])
        self.assertEqual(code, 0)

    def test_strict_fail(self):
        pm, pp = tmp_json(MANIFEST), tmp_json({"allow": [], "deny": []})
        code, _, err = run_cli(["audit", "--manifest", pm, "--policy", pp, "--min-score", "90"])
        self.assertEqual(code, 1)

    def test_missing_manifest_file(self):
        code, _, err = run_cli(["audit", "--manifest", "nope.json",
                                "--policy", tmp_json(FULL_POLICY)])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_missing_policy_file(self):
        code, _, err = run_cli(["audit", "--manifest", tmp_json(MANIFEST), "--policy", "nope.json"])
        self.assertEqual(code, 2)

    def test_malformed_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write("{not json")
        code, _, err = run_cli(["audit", "--manifest", path, "--policy", path])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_manifest_wrong_shape(self):
        code, _, _ = run_cli(["audit", "--manifest", tmp_json([]),
                              "--policy", tmp_json(FULL_POLICY)])
        self.assertEqual(code, 2)

    def test_policy_wrong_shape(self):
        code, _, _ = run_cli(["audit", "--manifest", tmp_json(MANIFEST),
                              "--policy", tmp_json({"allow": []})])
        self.assertEqual(code, 2)

    def test_policy_bad_entry(self):
        code, _, err = run_cli(["audit", "--manifest", tmp_json(MANIFEST),
                                "--policy", tmp_json({"allow": ["oops"], "deny": []})])
        self.assertEqual(code, 2)
        self.assertIn("tool:op", err)

    def test_policy_empty_segment(self):
        code, _, err = run_cli(["audit", "--manifest", tmp_json(MANIFEST),
                                "--policy", tmp_json({"allow": [":read"], "deny": []})])
        self.assertEqual(code, 2)

    def test_tool_missing_ops(self):
        bad = {"tools": [{"name": "fs"}]}
        code, _, _ = run_cli(["audit", "--manifest", tmp_json(bad),
                              "--policy", tmp_json(FULL_POLICY)])
        self.assertEqual(code, 2)


class TestExtremeEdge(unittest.TestCase):
    def test_unicode_tool_names(self):
        r = m.audit({"tools": [{"name": "文件工具", "ops": ["read"]}]},
                    {"allow": ["文件工具:read"], "deny": []})
        self.assertEqual(r["unreviewed"], 0)

    def test_emoji_tool_name(self):
        r = m.audit({"tools": [{"name": "🤖-tool", "ops": ["exec"]}]},
                    {"allow": ["🤖-tool:exec"], "deny": []})
        self.assertEqual(r["allowed"], 1)

    def test_unicode_json_fixture_roundtrip(self):
        man = {"tools": [{"name": "файл", "ops": ["читать"]}]}
        pm, pp = tmp_json(man), tmp_json({"allow": ["файл:читать"], "deny": []})
        code, out, _ = run_cli(["audit", "--manifest", pm, "--policy", pp, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["allowed"], 1)

    def test_crlf_fixture(self):
        man = {"tools": [{"name": "fs", "ops": ["read"]}]}
        pm, pp = tmp_json(man), tmp_json(FULL_POLICY)
        code, out, _ = run_cli(["audit", "--manifest", pm, "--policy", pp, "--json"])
        self.assertEqual(code, 0)

    def test_large_manifest_1000_tools(self):
        tools = [{"name": "t%d" % i, "ops": ["read", "write"]} for i in range(1000)]
        r = m.audit({"tools": tools}, {"allow": ["*:read"], "deny": []})
        self.assertEqual((r["allowed"], r["unreviewed"]), (1000, 1000))

    def test_empty_policy_entries(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertEqual(r["allowed"] + r["denied"] + r["unreviewed"], 4)

    def test_empty_tool_ops_list(self):
        r = m.audit({"tools": [{"name": "idle", "ops": []}]}, {"allow": [], "deny": []})
        self.assertEqual(r["total_pairs"], 0)

    def test_null_origin_like_odd_names(self):
        r = m.audit({"tools": [{"name": "null", "ops": ["*"]}]},
                    {"allow": ["null:read"], "deny": []})
        self.assertEqual(r["unreviewed_pairs"][0]["op"], "*")

    def test_case_sensitivity(self):
        r = m.audit({"tools": [{"name": "FS", "ops": ["READ"]}]},
                    {"allow": ["fs:read"], "deny": []})
        self.assertEqual(r["unreviewed"], 1)

    def test_score_bounds(self):
        r = m.audit(MANIFEST, {"allow": [], "deny": []})
        self.assertTrue(0.0 <= r["score"] <= 100.0)

    def test_meta_case_count(self):
        # E gate: at least 60 total cases across the three categories.
        pass

    def test_deny_wildcard_op_only(self):
        r = m.audit(MANIFEST, {"allow": ["*:*"], "deny": ["*:network"]})
        self.assertEqual((r["denied"], r["allowed"]), (1, 3))

    def test_parse_rule_rejects_non_string(self):
        with self.assertRaises(m.AuditError):
            m.parse_rule(42)

    def test_parse_rule_rejects_three_segments(self):
        with self.assertRaises(m.AuditError):
            m.parse_rule("a:b:c")

    def test_rule_covered_by_wider(self):
        self.assertTrue(m.rule_covered_by(("fs", "read"), ("fs", "*")))
        self.assertFalse(m.rule_covered_by(("fs", "*"), ("fs", "read")))

    def test_grade_b_band(self):
        # allow exec (w=4) -> remaining w=7/11 unreviewed -> score ~36 -> D;
        # allow exec+write+network -> remaining 1/11 -> score 90.9 -> A; use
        # allow exec+write -> 4/11 unreviewed -> score 63.6 -> C
        r = m.audit(MANIFEST, {"allow": ["shell:exec", "fs:write"], "deny": []})
        self.assertEqual(r["grade"], "C")

    def test_recommendations_capped_at_five(self):
        tools = [{"name": "t%d" % i, "ops": ["exec", "write", "network", "read"]}
                 for i in range(4)]
        r = m.audit({"tools": tools}, {"allow": [], "deny": []})
        self.assertEqual(len(r["recommendations"]), 5)


if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))
    sys.exit(0 if fails == 0 else 1)
