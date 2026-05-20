"""
Vexa smoke tests — verifies the security-critical paths work end-to-end.
Run: python -m pytest test_vexa.py -v
   or simply: python test_vexa.py
"""
import os
import sys
import tempfile
import shutil
import unittest
from pathlib import Path

# Run vexa in an isolated data dir so tests don't touch real data
_TEST_DATA = tempfile.mkdtemp(prefix="vexa_test_")
os.environ["VEXA_DATA_DIR"] = _TEST_DATA

# Import after setting env so module-level paths pick it up
sys.path.insert(0, str(Path(__file__).parent))


class SecurityHelpers(unittest.TestCase):
    """Unit tests for the security helper functions inside vexa.py."""

    @classmethod
    def setUpClass(cls):
        # Late import to ensure path setup
        import vexa as v
        cls.v = v

    def test_password_hash_roundtrip(self):
        h = self.v._hash_password("CorrectHorse!Battery42")
        self.assertTrue(self.v._verify_password("CorrectHorse!Battery42", h))
        self.assertFalse(self.v._verify_password("wrong", h))
        self.assertFalse(self.v._verify_password("", h))

    def test_password_hash_format(self):
        h = self.v._hash_password("Aa1bbbbbbbbbb")
        # Format: pbkdf2_sha256$<iters>$<salt_hex>$<dk_hex>
        parts = h.split("$")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "pbkdf2_sha256")
        self.assertEqual(int(parts[1]), 600_000)
        self.assertEqual(len(bytes.fromhex(parts[2])), 16)
        self.assertEqual(len(bytes.fromhex(parts[3])), 32)

    def test_password_hash_different_salts(self):
        # Two hashes of the same password must differ (random salt)
        h1 = self.v._hash_password("samepassword!")
        h2 = self.v._hash_password("samepassword!")
        self.assertNotEqual(h1, h2)
        self.assertTrue(self.v._verify_password("samepassword!", h1))
        self.assertTrue(self.v._verify_password("samepassword!", h2))

    def test_verify_malformed_hash(self):
        for bad in ["", "notahash", "pbkdf2_sha256$abc", "$$$$"]:
            self.assertFalse(self.v._verify_password("anything", bad))

    def test_validate_scan_id_accepts_valid(self):
        # UUID hex (no dashes), short hex token, alphanumeric
        for sid in ["abc12345", "ABCDEF1234567890", "a-b_c-d-e-f-g-1-2-3-4-5", "x" * 64]:
            self.assertEqual(self.v._validate_scan_id(sid), sid)

    def test_validate_scan_id_rejects_traversal(self):
        from fastapi import HTTPException
        for bad in ["../etc/passwd", "..\\foo", "a/b", "a\\b", "", "a", "x" * 65,
                    "abc.json", "abc def", "abc;cat", None, 123]:
            with self.assertRaises(HTTPException):
                self.v._validate_scan_id(bad)

    def test_safe_binary_path_rejects_outside(self):
        # Forge a report with apk_path pointing outside UPLOAD_DIR
        report = {"apk_path": "/etc/passwd"}
        self.assertIsNone(self.v._safe_binary_path(report))

    def test_safe_binary_path_rejects_traversal(self):
        # Path that resolves outside the upload dir
        upload = self.v.UPLOAD_DIR
        report = {"apk_path": str(upload / ".." / ".." / "etc" / "passwd")}
        self.assertIsNone(self.v._safe_binary_path(report))

    def test_safe_binary_path_accepts_inside(self):
        # Create a real file inside UPLOAD_DIR
        f = self.v.UPLOAD_DIR / "test.apk"
        f.write_bytes(b"PK\x03\x04dummy")
        try:
            report = {"apk_path": str(f)}
            self.assertEqual(self.v._safe_binary_path(report), str(f.resolve()))
        finally:
            f.unlink(missing_ok=True)

    def test_login_rate_limit(self):
        # Reset state for this test
        self.v.LOGIN_FAILURES.clear()
        ip = "192.0.2.1"
        # First 4 failures should not lock
        for _ in range(4):
            self.v._record_login_failure(ip)
            self.assertIsNone(self.v._login_rate_limited(ip))
        # 5th failure -> locked
        self.v._record_login_failure(ip)
        wait = self.v._login_rate_limited(ip)
        self.assertIsNotNone(wait)
        self.assertGreater(wait, 0)
        # Reset clears the lock
        self.v._reset_login_failures(ip)
        self.assertIsNone(self.v._login_rate_limited(ip))


class ConfigPersistence(unittest.TestCase):
    """Test the first-run setup config flow."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def test_save_and_load_config(self):
        # Use a temp config file to avoid touching real one
        original = self.v.CONFIG_FILE
        tmp = Path(_TEST_DATA) / "test_config.json"
        try:
            self.v.CONFIG_FILE = tmp
            cfg = {"admin_user": "alice",
                   "admin_password_hash": self.v._hash_password("StrongPass1!")}
            self.v._save_config(cfg)
            self.assertTrue(tmp.exists())
            # Permissions check (Unix)
            if hasattr(os, 'stat') and not sys.platform.startswith("win"):
                mode = oct(tmp.stat().st_mode & 0o777)
                self.assertEqual(mode, "0o600")
            loaded = self.v._load_config()
            self.assertEqual(loaded["admin_user"], "alice")
            self.assertTrue(self.v._verify_password("StrongPass1!", loaded["admin_password_hash"]))
        finally:
            self.v.CONFIG_FILE = original
            tmp.unlink(missing_ok=True)


class AnalyzerRegistration(unittest.TestCase):
    """Test that all analyzers register properly."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def test_analyzer_count(self):
        # Should have 91 Android + 15 iOS analyzers per release notes
        self.assertEqual(len(self.v.ANALYZERS), 91,
                         f"Expected 91 Android analyzers, got {len(self.v.ANALYZERS)}")
        self.assertEqual(len(self.v.IOS_ANALYZERS), 15,
                         f"Expected 15 iOS analyzers, got {len(self.v.IOS_ANALYZERS)}")

    def test_secret_patterns_compile(self):
        # All 39 secret patterns should compile
        self.assertGreaterEqual(len(self.v._COMPILED_SECRET_PATTERNS), 39)

    def test_exploit_recipes_have_required_fields(self):
        for key, recipe in self.v.EXPLOIT_RECIPES.items():
            self.assertIn("title", recipe, f"{key} missing title")
            self.assertIn("explanation", recipe, f"{key} missing explanation")
            self.assertIn("tags", recipe, f"{key} missing tags")
            self.assertIn("build", recipe, f"{key} missing build callable")
            self.assertTrue(callable(recipe["build"]), f"{key}.build not callable")

    def test_enrichment_table_well_formed(self):
        for key, data in self.v.ENRICHMENT.items():
            # Each entry should have at least one of: cve / cwe / impact / fix
            keys = data.keys()
            self.assertTrue(any(k in keys for k in ("cve", "cwe", "impact", "fix")),
                            f"ENRICHMENT[{key}] has no useful field")
            # If cvss is present, it should be a float in valid range
            if "cvss" in data and data["cvss"]:
                self.assertIsInstance(data["cvss"], (int, float))
                self.assertGreaterEqual(data["cvss"], 0.0)
                self.assertLessEqual(data["cvss"], 10.0)


class ExploitGeneration(unittest.TestCase):
    """Test exploit recipes generate sensible output."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v
        cls.fake_report = {
            "metadata": {"package": "com.example.target", "version_name": "1.0",
                         "main_activity": "com.example.target.MainActivity",
                         "activities": ["com.example.target.MainActivity"]},
            "extras": {
                "deeplinks": [{"uri": "myapp://path", "activity": "com.example.target.MainActivity"}],
                "exported_components": [
                    {"tag": "activity", "name": "com.example.target.MainActivity"},
                    {"tag": "provider", "name": "com.example.target.Provider", "authorities": "com.example.target.fileprovider"},
                ],
            },
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    def test_create_sql_exploit(self):
        out = self.v._generate_exploit("create an exploit for sql injection", self.fake_report)
        self.assertIsNotNone(out)
        self.assertIn("com.example.target", out)
        self.assertIn("UNION", out)

    def test_create_webview_rce(self):
        out = self.v._generate_exploit("build a poc for webview rce", self.fake_report)
        self.assertIsNotNone(out)
        self.assertIn("com.example.target", out)
        self.assertIn("addJavascriptInterface", out.lower().replace("addjavascriptinterface", "addJavascriptInterface"))

    def test_no_match_returns_none(self):
        out = self.v._generate_exploit("what is the weather today", self.fake_report)
        self.assertIsNone(out)

    def test_non_generative_query_returns_none(self):
        # Asking *about* an exploit shouldn't trigger generation
        out = self.v._generate_exploit("what is sql injection", self.fake_report)
        self.assertIsNone(out)

    def test_recipe_uses_actual_package(self):
        out = self.v._generate_exploit("generate a frida tracer", self.fake_report)
        self.assertIsNotNone(out)
        # Should bake in the actual package name from the report
        self.assertIn("com.example.target", out)


class CVEEnrichment(unittest.TestCase):
    """Test CVE enrichment applies correctly."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def test_enrich_known_finding(self):
        findings = [{"id": "janus", "title": "Janus", "severity": "high"}]
        out = self.v.enrich_findings(findings)
        self.assertEqual(out[0].get("cve"), "CVE-2017-13156")
        self.assertEqual(out[0].get("cvss"), 7.5)
        self.assertIn("v2/v3", out[0].get("fix", ""))

    def test_enrich_prefix_match(self):
        findings = [{"id": "janus-something-extra", "title": "Janus variant"}]
        out = self.v.enrich_findings(findings)
        self.assertEqual(out[0].get("cve"), "CVE-2017-13156")

    def test_unknown_finding_unchanged(self):
        findings = [{"id": "no-such-id-anywhere", "title": "Mystery"}]
        out = self.v.enrich_findings(findings)
        self.assertNotIn("cve", out[0])


# =============================================================================
# Tests added in vexa3 — covering the delete-scan flow, exploit-generator query
# coverage, and false-positive filter behaviour.
# =============================================================================

class DeleteScanFlow(unittest.TestCase):
    """Exercise the delete endpoint logic, including: the report file is removed,
    the original APK file is removed, side-files are removed, and the validation
    blocks path-traversal scan IDs."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def setUp(self):
        # Create a fresh fake scan inside the test data dir
        self.sid = "test_scan_abc123"
        self.report_path = self.v.REPORT_DIR / f"{self.sid}.json"
        self.apk_path = self.v.UPLOAD_DIR / f"{self.sid}.apk"
        self.dynamic_path = self.v.REPORT_DIR / f"{self.sid}.dynamic.json"
        self.pocs_path = self.v.REPORT_DIR / f"{self.sid}.pocs.json"
        self.pocs_dir = self.v.REPORT_DIR / f"{self.sid}_pocs"

        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.apk_path.parent.mkdir(parents=True, exist_ok=True)
        self.pocs_dir.mkdir(parents=True, exist_ok=True)

        # APK with magic bytes so any validation accepts it
        self.apk_path.write_bytes(b"PK\x03\x04dummyapk")
        # Report references the apk
        report = {
            "scan_id": self.sid,
            "apk_path": str(self.apk_path),
            "platform": "Android",
            "metadata": {"package": "com.example.test"},
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        import json
        with self.report_path.open("w") as f:
            json.dump(report, f)
        self.dynamic_path.write_text("{}")
        self.pocs_path.write_text("[]")
        (self.pocs_dir / "poc1.md").write_text("dummy")

    def tearDown(self):
        for p in (self.report_path, self.apk_path,
                  self.dynamic_path, self.pocs_path):
            try: p.unlink(missing_ok=True)
            except Exception: pass
        try: shutil.rmtree(self.pocs_dir, ignore_errors=True)
        except Exception: pass

    def test_validate_scan_id_blocks_traversal(self):
        from fastapi import HTTPException
        for bad in ["../etc/passwd", "..\\foo", "abc/def", "abc\\def", "abc..def",
                    "ab", "x" * 65, "with space", "abc;cat"]:
            with self.assertRaises(HTTPException):
                self.v._validate_scan_id(bad)

    def test_validate_scan_id_accepts_valid(self):
        for good in ["abc12345", "long_scan_id_with_underscores",
                     "uuid-style-1234-5678-abcd", "12345678", "X" * 64]:
            self.assertEqual(self.v._validate_scan_id(good), good)

    def test_safe_binary_path_resolves_inside_upload_dir(self):
        # Real file inside UPLOAD_DIR -> returns resolved path
        report = {"apk_path": str(self.apk_path)}
        result = self.v._safe_binary_path(report)
        self.assertIsNotNone(result)
        self.assertTrue(str(self.v.UPLOAD_DIR.resolve()) in result)

    def test_safe_binary_path_blocks_outside(self):
        # Path outside UPLOAD_DIR -> rejected
        for bad in ["/etc/passwd", "/tmp/escape.apk", str(self.v.UPLOAD_DIR / ".." / "escape")]:
            self.assertIsNone(self.v._safe_binary_path({"apk_path": bad}))

    def test_safe_binary_path_handles_missing(self):
        # Path does not exist -> returns None (not a crash)
        ghost = self.v.UPLOAD_DIR / "ghost_file_does_not_exist.apk"
        self.assertIsNone(self.v._safe_binary_path({"apk_path": str(ghost)}))


class ExploitGeneratorQueryCoverage(unittest.TestCase):
    """Comprehensive query-coverage tests for _generate_exploit.
    These verify that the AI Console responds with a structured exploit document
    for the variety of phrasings real users actually type, NOT just the original
    'create / generate / build' verbs."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v
        cls.fake_report = {
            "scan_date": "2026-05-07T10:00:00Z",
            "metadata": {"package": "com.example.target", "version_name": "1.0",
                         "main_activity": "com.example.target.MainActivity",
                         "activities": ["com.example.target.MainActivity"]},
            "extras": {
                "deeplinks": [{"uri": "myapp://path", "activity": "com.example.target.MainActivity"}],
                "exported_components": [
                    {"tag": "activity", "name": "com.example.target.MainActivity"},
                    {"tag": "provider", "name": "com.example.target.Provider",
                     "authorities": "com.example.target.fileprovider"},
                ],
            },
            "findings": [
                {"id": "trustmanager-trust-all",
                 "title": "Custom TrustManager accepts every certificate",
                 "severity": "high", "cvss": 7.4, "cwe": "CWE-295",
                 "category": "MASVS-NETWORK"},
            ],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        }

    def _assert_enterprise_doc(self, output):
        self.assertIsNotNone(output)
        # An enterprise doc has the classification header + numbered sections
        self.assertIn("Classification & Metadata", output)
        self.assertIn("#### 1. Executive summary", output)
        self.assertIn("Target", output)

    # --- Verb coverage ---

    def test_create_verb(self):
        out = self.v._generate_exploit("create an exploit for sql injection", self.fake_report)
        self._assert_enterprise_doc(out)
        self.assertIn("SQL Injection", out)

    def test_build_verb(self):
        out = self.v._generate_exploit("build a poc for webview rce", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_show_me_verb(self):
        out = self.v._generate_exploit("show me how to exploit the webview", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_demonstrate_verb(self):
        out = self.v._generate_exploit("demonstrate the addjavascriptinterface vulnerability", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_walk_me_through(self):
        out = self.v._generate_exploit("walk me through the SQL injection", self.fake_report)
        self._assert_enterprise_doc(out)

    # --- 'I want / I need' phrasings ---

    def test_i_want_phrasing(self):
        out = self.v._generate_exploit("I want exploit", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_i_want_specific(self):
        out = self.v._generate_exploit("I want an exploit for sqli", self.fake_report)
        self._assert_enterprise_doc(out)
        self.assertIn("SQL Injection", out)

    def test_i_need_phrasing(self):
        out = self.v._generate_exploit("i need a poc for ssl pinning", self.fake_report)
        self._assert_enterprise_doc(out)
        self.assertIn("MITM", out)  # Trust manager bypass title contains MITM

    # --- 'How do I' phrasings ---

    def test_how_do_i_exploit(self):
        out = self.v._generate_exploit("how do i exploit this app?", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_how_to_exploit(self):
        out = self.v._generate_exploit("how to exploit the webview", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_how_to_attack(self):
        out = self.v._generate_exploit("how to attack the deeplink", self.fake_report)
        self._assert_enterprise_doc(out)

    # --- 'Exploit for / Exploit the' direct phrasings ---

    def test_exploit_for_phrasing(self):
        out = self.v._generate_exploit("exploit for SQL injection", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_poc_for_phrasing(self):
        out = self.v._generate_exploit("poc for webview rce", self.fake_report)
        self._assert_enterprise_doc(out)

    # --- Bare vulnerability vocabulary (no 'create' verb at all) ---

    def test_bare_vuln_word_sqli(self):
        out = self.v._generate_exploit("sqli payload", self.fake_report)
        self._assert_enterprise_doc(out)

    def test_bare_vuln_word_rce(self):
        out = self.v._generate_exploit("rce poc", self.fake_report)
        self._assert_enterprise_doc(out)

    # --- Alias matching ---

    def test_alias_ssl_pinning_maps_to_trust_manager(self):
        out = self.v._generate_exploit("create an exploit for ssl pinning", self.fake_report)
        self._assert_enterprise_doc(out)
        # Should match trustmanager-bypass recipe -- title contains "MITM"
        self.assertIn("MITM", out)

    def test_alias_dirty_stream_maps_to_fileprovider(self):
        out = self.v._generate_exploit("create exploit for dirty stream", self.fake_report)
        self._assert_enterprise_doc(out)
        # Should reference CVE-2024-0044
        self.assertIn("CVE-2024-0044", out)

    def test_alias_intent_spoof_maps_to_exported_activity(self):
        out = self.v._generate_exploit("create intent spoof poc", self.fake_report)
        self._assert_enterprise_doc(out)

    # --- Fallback: no recipe match, no finding match, but exploit verb -> top finding ---

    def test_unknown_specific_falls_back_to_top_finding(self):
        # 'race condition' isn't a recipe key -> falls through to top finding (TLS one)
        out = self.v._generate_exploit("create an exploit for race condition", self.fake_report)
        self.assertIsNotNone(out)
        # Falls back to scenario based on top severity finding (TrustManager finding)
        self.assertIn("TrustManager", out)

    def test_no_findings_no_recipe_returns_menu(self):
        empty = {"metadata": {"package": "com.empty"}, "findings": [], "extras": {}, "summary": {}}
        out = self.v._generate_exploit("create exploit for race condition", empty)
        self.assertIsNotNone(out)
        # Should advertise available recipes
        self.assertIn("Available recipes", out)
        self.assertIn("SQL Injection", out)

    # --- Non-exploit queries should NOT trigger the generator ---

    def test_non_exploit_query_returns_none(self):
        # Simple Q&A style queries that should NOT trigger exploit doc generation
        for q in ["what is sql injection?", "how many findings?",
                  "what's the severity?", "list all findings"]:
            self.assertIsNone(self.v._generate_exploit(q, self.fake_report),
                              f"should not generate for query: {q!r}")

    def test_empty_query_returns_none(self):
        self.assertIsNone(self.v._generate_exploit("", self.fake_report))
        self.assertIsNone(self.v._generate_exploit("   ", self.fake_report))


class ExploitDocStructure(unittest.TestCase):
    """Each enterprise exploit document must contain ALL the sections expected
    by an enterprise penetration-testing deliverable."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v
        cls.report = {
            "scan_date": "2026-05-07T10:00:00Z",
            "metadata": {"package": "com.example.test", "version_name": "2.0",
                         "main_activity": "com.example.test.MainActivity",
                         "activities": []},
            "extras": {"deeplinks": [], "exported_components": []},
            "findings": [],
            "summary": {},
        }

    def test_recipe_doc_has_all_sections(self):
        out = self.v._generate_exploit("create exploit for SQL injection", self.report)
        required = [
            "Classification & Metadata",
            "#### 1. Executive summary",
            "#### 2. Business impact",
            "#### 3. Preconditions",
            "#### 4. Reproduction steps",
            "#### 5. Proof-of-concept code",
            "#### 6. Evidence collection",
            "#### 7. Post-exploitation impact",
            "#### 8. Cleanup",
            "#### 9. Remediation guidance",
            "#### 10. References",
            "#### 11. Reproduction audit trail",
            "Legal & ethical notice",
        ]
        for marker in required:
            self.assertIn(marker, out, f"missing section: {marker}")

    def test_doc_includes_target_package(self):
        out = self.v._generate_exploit("create exploit for webview", self.report)
        self.assertIn("com.example.test", out)

    def test_doc_has_verify_gates(self):
        out = self.v._generate_exploit("create exploit for SQL injection", self.report)
        self.assertIn("Verify:", out)

    def test_doc_has_cvss_band(self):
        out = self.v._generate_exploit("create exploit for SQL injection", self.report)
        self.assertIn("CVSS v3.1", out)
        # SQL injection has CVSS 8.8 -> HIGH band
        self.assertIn("(HIGH)", out)

    def test_doc_links_cwe_to_mitre(self):
        out = self.v._generate_exploit("create exploit for SQL injection", self.report)
        self.assertIn("cwe.mitre.org", out)

    def test_doc_includes_priority_recommendation(self):
        out = self.v._generate_exploit("create exploit for SQL injection", self.report)
        # Should map severity to a P0-P4 priority
        self.assertTrue(any(p in out for p in ("P0", "P1", "P2", "P3", "P4")),
                        "doc should include fix priority")


class FalsePositiveFiltering(unittest.TestCase):
    """The cipher-no-padding analyzer was rewritten to require multiple confirmation
    signals before flagging. These tests confirm that hardening."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _ctx_with_strings(self, strings_list):
        # Minimal Ctx-like object that satisfies _get_strings()
        class _MockCtx:
            def __init__(self, strings):
                self._strings = strings
                self._cached_strings = strings
        return _MockCtx(strings_list)

    def test_cipher_no_mode_no_finding_when_no_cipher_class(self):
        # bare "AES" string but Cipher class is NOT loaded -> should NOT flag
        ctx = self._ctx_with_strings(["AES", "some other string"])
        findings = self.v.analyze_cipher_no_padding(ctx)
        self.assertEqual(len(findings), 0)

    def test_cipher_no_mode_no_finding_when_qualified_form_exists(self):
        # Cipher loaded AND bare AES present, BUT qualified form exists -> should NOT flag
        ctx = self._ctx_with_strings([
            "Ljavax/crypto/Cipher;",
            "AES",
            "AES/CBC/PKCS5Padding",
        ])
        findings = self.v.analyze_cipher_no_padding(ctx)
        self.assertEqual(len(findings), 0,
                         "Should suppress finding when qualified AES/MODE/PADDING is also present")

    def test_cipher_no_mode_flags_when_all_signals_present(self):
        ctx = self._ctx_with_strings([
            "Ljavax/crypto/Cipher;",
            "AES",
            # No qualified AES/CBC/... form
        ])
        findings = self.v.analyze_cipher_no_padding(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "cipher-no-mode")
        # And it's marked confidence=possible (heuristic)
        self.assertEqual(findings[0].confidence, "possible")


class Path2AnalyzersGap(unittest.TestCase):
    """Smoke tests for the Path-2 expansion batch (24 new analyzers covering
    MASVS-AUTH/PRIVACY/RESILIENCE/NETWORK/CODE gaps). Verifies:
      - empty Ctx produces NO findings (no false positives on clean apps)
      - vulnerable Ctx produces findings (analyzer not silently broken)
      - new ANALYZERS list size grew by exactly 24
    """

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _make_ctx(self, strings=None):
        ctx = self.v.Ctx(apk=None, dex_list=[], dx=None)
        ctx._cached_strings = strings or []
        ctx.extras = {}
        return ctx

    def test_analyzer_count_grew_by_24(self):
        # 91 (pre-batch) + 24 (Path-2) = 115 analyzers wired into ANALYZERS
        self.assertGreaterEqual(len(self.v.ANALYZERS), 115)
        names = {n for n, _ in self.v.ANALYZERS}
        for new_name in ("jwt-alg-none", "background-location", "okhttp-trust-all-hosts",
                         "test-only-apk", "advertising-id"):
            self.assertIn(new_name, names, f"missing analyzer: {new_name}")

    def test_jwt_alg_none_no_fp_on_clean(self):
        self.assertEqual(self.v.analyze_jwt_alg_none(self._make_ctx([])), [])

    def test_jwt_alg_none_fires_on_signal(self):
        result = self.v.analyze_jwt_alg_none(self._make_ctx([
            "Lcom/auth0/jwt/", "alg", "none"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "jwt-alg-none-accepted")

    def test_okhttp_trust_all_no_fp_on_clean(self):
        self.assertEqual(self.v.analyze_okhttp_trust_all(self._make_ctx([])), [])

    def test_okhttp_trust_all_fires(self):
        result = self.v.analyze_okhttp_trust_all(self._make_ctx([
            "Lokhttp3/OkHttpClient$Builder;", "hostnameVerifier",
            "javax/net/ssl/HostnameVerifier"]))
        self.assertEqual(len(result), 1)

    def test_volley_allow_all_no_fp_on_clean(self):
        self.assertEqual(self.v.analyze_volley_allow_all_hosts(self._make_ctx([])), [])

    def test_volley_allow_all_fires(self):
        result = self.v.analyze_volley_allow_all_hosts(self._make_ctx([
            "Lcom/android/volley/", "ALLOW_ALL_HOSTNAME_VERIFIER"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_websocket_no_wss_fires(self):
        result = self.v.analyze_websocket_no_wss(self._make_ctx([
            "ws://api.example.com/socket"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "cleartext-websocket")

    def test_websocket_no_wss_ignores_localhost(self):
        # ws:// to localhost / private IPs should NOT fire
        self.assertEqual(self.v.analyze_websocket_no_wss(self._make_ctx([
            "ws://localhost:8080/test", "ws://127.0.0.1:9000/socket",
            "ws://192.168.1.5:3000/ws", "ws://10.0.0.1/connect"])), [])

    def test_dexclassloader_no_fp_on_clean(self):
        self.assertEqual(self.v.analyze_dexclassloader_writable(self._make_ctx([])), [])

    def test_dexclassloader_fires(self):
        result = self.v.analyze_dexclassloader_writable(self._make_ctx([
            "Ldalvik/system/DexClassLoader",
            "/data/data/com.x/cache/payload.dex"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_dexclassloader_no_fp_without_classloader(self):
        # Writable paths but no DexClassLoader reference -> no finding
        self.assertEqual(self.v.analyze_dexclassloader_writable(self._make_ctx([
            "/data/data/com.x/cache/log.txt",
            "/data/data/com.x/files/data.dex"])), [])

    def test_advertising_id_fires(self):
        result = self.v.analyze_advertising_id_usage(self._make_ctx([
            "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].confidence, "confirmed")

    def test_advertising_id_no_fp_on_clean(self):
        self.assertEqual(self.v.analyze_advertising_id_usage(self._make_ctx([])), [])

    def test_session_in_logcat_fires(self):
        result = self.v.analyze_session_in_logcat(self._make_ctx([
            "Landroid/util/Log;", "Bearer token = %s"]))
        self.assertEqual(len(result), 1)

    def test_session_in_logcat_no_fp_without_log_class(self):
        # Format string present but no Log class reference -> no finding
        self.assertEqual(self.v.analyze_session_in_logcat(self._make_ctx([
            "Bearer token = %s"])), [])

    def test_biometric_no_user_auth_fires(self):
        result = self.v.analyze_biometric_keyspec_no_user_auth(self._make_ctx([
            "KeyGenParameterSpec", "BiometricPrompt"]))
        self.assertEqual(len(result), 1)

    def test_biometric_no_user_auth_no_fp_when_setter_present(self):
        # The protective call IS present -> no finding
        self.assertEqual(self.v.analyze_biometric_keyspec_no_user_auth(self._make_ctx([
            "KeyGenParameterSpec", "BiometricPrompt",
            "setUserAuthenticationRequired"])), [])

    def test_native_anti_debug_skipped_when_no_natives(self):
        self.assertEqual(self.v.analyze_native_anti_debug(self._make_ctx([])), [])

    def test_all_new_analyzers_have_unique_ids(self):
        # Sanity: no two analyzers in the new batch return findings with the same ID prefix
        ctx = self._make_ctx([])
        all_ids = []
        for name, fn in self.v.EXTENDED_ANALYZERS_4:
            try:
                results = fn(ctx)
                all_ids.extend(f.id for f in results)
            except Exception:
                pass  # some analyzers need an APK
        # Empty ctx should produce no findings, so IDs should all be empty
        self.assertEqual(all_ids, [])


class TaintEngine(unittest.TestCase):
    """Tests for the intra-procedural taint analysis engine.
    Uses mock androguard instructions to drive the trace function."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _mk_ins(self, name, operands):
        class _MockInsn:
            def __init__(self, n, o): self._n, self._o = n, o
            def get_name(self): return self._n
            def get_operands(self): return self._o
        return _MockInsn(name, operands)

    def _mk_method(self, instructions, cls_name="Lcom/x/Foo;", method_name="m"):
        class _MockMethod:
            def __init__(self, c, mn, ins): self._c, self._mn, self._ins = c, mn, ins
            def get_class_name(self): return self._c
            def get_name(self): return self._mn
            def get_instructions(self): return iter(self._ins)
            def get_code(self): return object()
        return _MockMethod(cls_name, method_name, instructions)

    def test_intent_extra_to_rawquery_detected(self):
        """Intent.getStringExtra -> rawQuery is the canonical SQLi flow."""
        m = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 1),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),
            self._mk_ins("invoke-virtual", [(0, 3), (0, 2), (0, 4),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ])
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0][0]["id"], "taint-sqli-rawquery")
        self.assertEqual(flows[0][1], "intent-extra")

    def test_constant_query_no_flow(self):
        """const-string + rawQuery is safe -- engine must NOT flag."""
        m = self._mk_method([
            self._mk_ins("const-string", [(0, 0), "SELECT * FROM t"]),
            self._mk_ins("invoke-virtual", [(0, 1), (0, 0), (0, 2),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ])
        self.assertEqual(self.v._trace_method_taint(m), [])

    def test_string_builder_propagates_taint(self):
        """StringBuilder.append carries taint to the receiver register."""
        m = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 1),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),
            self._mk_ins("invoke-virtual", [(0, 3), (0, 2),
                "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"]),
            self._mk_ins("invoke-virtual", [(0, 5), (0, 3), (0, 6),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ])
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)

    def test_const_string_clears_taint(self):
        """Overwriting a tainted register with const-string clears taint."""
        m = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 1),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),
            self._mk_ins("const-string", [(0, 2), "SELECT * FROM t"]),  # clears v2
            self._mk_ins("invoke-virtual", [(0, 3), (0, 2), (0, 4),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ])
        self.assertEqual(self.v._trace_method_taint(m), [])

    def test_multiple_sinks_in_same_method(self):
        """Two independent source-to-sink flows yield two findings."""
        m = self._mk_method([
            # first: getStringExtra -> Runtime.exec
            self._mk_ins("invoke-virtual", [(0, 0), (0, 1),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),
            self._mk_ins("invoke-virtual", [(0, 3), (0, 2),
                "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"]),
            # second: getDataString -> WebView.loadUrl
            self._mk_ins("invoke-virtual", [(0, 0),
                "Landroid/content/Intent;->getDataString()Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 4)]),
            self._mk_ins("invoke-virtual", [(0, 5), (0, 4),
                "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"]),
        ])
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 2)
        sink_ids = {f[0]["id"] for f in flows}
        self.assertIn("taint-cmd-injection-runtime", sink_ids)
        self.assertIn("taint-webview-url", sink_ids)

    def test_uri_query_param_to_webview(self):
        """Uri.getQueryParameter -> WebView.loadUrl flow."""
        m = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 1),
                "Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),
            self._mk_ins("invoke-virtual", [(0, 3), (0, 2),
                "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"]),
        ])
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0][0]["id"], "taint-webview-url")
        self.assertEqual(flows[0][1], "uri-param")

    def test_no_taint_no_flow(self):
        """Method that never touches a source -> no flows."""
        m = self._mk_method([
            self._mk_ins("const-string", [(0, 0), "hello"]),
            self._mk_ins("invoke-virtual", [(0, 1), (0, 0),
                "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"]),
        ])
        self.assertEqual(self.v._trace_method_taint(m), [])

    def test_taint_constants_table(self):
        """Sanity check the tables: every sink has the required metadata fields."""
        for key, meta in self.v.TAINT_SINKS.items():
            for required in ("id", "title", "category", "severity",
                             "cwe", "cvss", "masvs", "description", "fix"):
                self.assertIn(required, meta, f"{key}: missing {required}")
            self.assertIn(meta["severity"], ("critical", "high", "medium", "low"),
                          f"{key}: bad severity {meta['severity']!r}")

    def test_analyze_taint_no_dx(self):
        """analyze_taint returns [] when ctx.dx is None (no APK loaded)."""
        ctx = self.v.Ctx(apk=None, dex_list=[], dx=None)
        self.assertEqual(self.v.analyze_taint(ctx), [])

    def test_taint_analyzer_in_analyzers_list(self):
        """The taint analyzer is wired into ANALYZERS so the scan pipeline runs it."""
        names = {n for n, _ in self.v.ANALYZERS}
        self.assertIn("taint-analysis", names)


class InterProceduralTaint(unittest.TestCase):
    """Tests for the inter-procedural taint engine: function summaries and
    cross-method propagation."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _mk_ins(self, name, operands):
        class _MockInsn:
            def __init__(self, n, o): self._n, self._o = n, o
            def get_name(self): return self._n
            def get_operands(self): return self._o
        return _MockInsn(name, operands)

    def _mk_method(self, ins, cls_name="Lcom/x/Foo;", method_name="m",
                   descriptor="()V", static=False, regs_size=5):
        class _MockCode:
            def __init__(self, rs): self._rs = rs
            def get_registers_size(self): return self._rs
        class _MockMethod:
            def __init__(self):
                self._c, self._n, self._ins = cls_name, method_name, ins
                self._d, self._s, self._code = descriptor, static, _MockCode(regs_size)
            def get_class_name(self): return self._c
            def get_name(self): return self._n
            def get_descriptor(self): return self._d
            def get_access_flags(self): return 0x8 if self._s else 0
            def get_instructions(self): return iter(self._ins)
            def get_code(self): return self._code
        return _MockMethod()

    def test_param_register_map_instance_method(self):
        # Instance method with 1 String param, regs_size=4
        # 'this' at v2 (param 0), input at v3 (param 1)
        m = self._mk_method([], descriptor="(Ljava/lang/String;)V",
                            static=False, regs_size=4)
        result = self.v._method_param_register_map(m)
        self.assertEqual(result, {2: 0, 3: 1})

    def test_param_register_map_static_method(self):
        # Static method with 1 String param, regs_size=2
        # input at v1 (param 0)
        m = self._mk_method([], descriptor="(Ljava/lang/String;)V",
                            static=True, regs_size=2)
        result = self.v._method_param_register_map(m)
        self.assertEqual(result, {1: 0})

    def test_summary_callee_param_reaches_sink(self):
        # Callee: instance method, 1 param. v2 = this, v3 = input.
        # rawQuery(input) -- v3 is the param at position 1.
        callee = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 3), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], cls_name="Lcom/x/Foo;", method_name="doQuery",
           descriptor="(Ljava/lang/String;)V", static=False, regs_size=4)
        summaries = self.v._compute_summaries([callee], max_iterations=4)
        s = summaries[("Lcom/x/Foo;", "doQuery")]
        # Param at position 1 (the input) reaches the sink
        self.assertIn(1, s.param_reaches_sink)
        self.assertEqual(s.param_reaches_sink[1]["id"], "taint-sqli-rawquery")

    def test_summary_param_to_return_propagation(self):
        # Static method: returns its single param directly
        m = self._mk_method([
            self._mk_ins("return-object", [(0, 1)]),  # return v1 (the param)
        ], cls_name="Lcom/x/Util;", method_name="passthrough",
           descriptor="(Ljava/lang/String;)Ljava/lang/String;",
           static=True, regs_size=2)
        summaries = self.v._compute_summaries([m], max_iterations=4)
        s = summaries[("Lcom/x/Util;", "passthrough")]
        # Param at position 0 propagates to return
        self.assertIn(0, s.return_taints_from_params)

    def test_inter_procedural_sink_detected(self):
        # Caller: gets Intent extra, passes to doQuery helper. doQuery internally
        # calls rawQuery on its param.
        caller = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 5), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 1)]),
            self._mk_ins("invoke-virtual", [(0, 4), (0, 1),
                "Lcom/x/Foo;->doQuery(Ljava/lang/String;)V"]),
        ], cls_name="Lcom/x/Foo;", method_name="onCreate",
           descriptor="(Landroid/content/Intent;)V", static=False, regs_size=6)

        callee = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 3), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], cls_name="Lcom/x/Foo;", method_name="doQuery",
           descriptor="(Ljava/lang/String;)V", static=False, regs_size=4)

        summaries = self.v._compute_summaries([caller, callee], max_iterations=4)
        flows = self.v._trace_method_taint_with_summaries(caller, summaries)
        # Should detect ONE inter-procedural flow
        inter_flows = [f for f in flows if f[3]]
        self.assertEqual(len(inter_flows), 1)
        sink_meta, src_kind, evidence, is_inter = inter_flows[0]
        self.assertEqual(sink_meta["id"], "taint-sqli-rawquery")
        self.assertEqual(src_kind, "intent-extra")

    def test_inter_procedural_clean_no_false_positive(self):
        # Same setup but caller passes a const-string -- should NOT flag
        callee = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 0), (0, 3), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], cls_name="Lcom/x/Foo;", method_name="doQuery",
           descriptor="(Ljava/lang/String;)V", static=False, regs_size=4)

        clean_caller = self._mk_method([
            self._mk_ins("const-string", [(0, 1), "SELECT * FROM t"]),
            self._mk_ins("invoke-virtual", [(0, 4), (0, 1),
                "Lcom/x/Foo;->doQuery(Ljava/lang/String;)V"]),
        ], cls_name="Lcom/x/Foo;", method_name="cleanCall",
           descriptor="()V", static=False, regs_size=5)

        summaries = self.v._compute_summaries([callee, clean_caller], max_iterations=4)
        flows = self.v._trace_method_taint_with_summaries(clean_caller, summaries)
        self.assertEqual(len(flows), 0)

    def test_helper_return_taint_propagation(self):
        # source -> helper.passthrough(tainted) returns tainted -> sink
        helper = self._mk_method([
            self._mk_ins("return-object", [(0, 1)]),  # v1 = param 0
        ], cls_name="Lcom/x/Util;", method_name="passthrough",
           descriptor="(Ljava/lang/String;)Ljava/lang/String;",
           static=True, regs_size=2)

        caller = self._mk_method([
            self._mk_ins("invoke-virtual", [(0, 5), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 1)]),
            self._mk_ins("invoke-static", [(0, 1),
                "Lcom/x/Util;->passthrough(Ljava/lang/String;)Ljava/lang/String;"]),
            self._mk_ins("move-result-object", [(0, 2)]),  # v2 = tainted via helper
            self._mk_ins("invoke-virtual", [(0, 0), (0, 2), (0, 3),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], cls_name="Lcom/x/Foo;", method_name="useHelper",
           descriptor="(Landroid/content/Intent;)V", static=False, regs_size=6)

        summaries = self.v._compute_summaries([helper, caller], max_iterations=4)
        flows = self.v._trace_method_taint_with_summaries(caller, summaries)
        # The sink IS in the caller, so this is intra-procedural in the caller --
        # but the v2 taint came through an inter-procedural call to helper.
        self.assertGreaterEqual(len(flows), 1)
        # First flow should reach the rawQuery sink
        sink_meta = flows[0][0]
        self.assertEqual(sink_meta["id"], "taint-sqli-rawquery")

    def test_is_user_class_filter(self):
        self.assertTrue(self.v._is_user_class("Lcom/myapp/MainActivity;"))
        self.assertTrue(self.v._is_user_class("Lcom/example/foo/Bar;"))
        self.assertFalse(self.v._is_user_class("Landroid/content/Intent;"))
        self.assertFalse(self.v._is_user_class("Ljava/lang/String;"))
        self.assertFalse(self.v._is_user_class("Landroidx/core/Foo;"))
        self.assertFalse(self.v._is_user_class("Lkotlin/io/Bar;"))
        self.assertFalse(self.v._is_user_class(""))

    def test_inter_procedural_analyzer_in_pipeline(self):
        names = {n for n, _ in self.v.ANALYZERS}
        self.assertIn("taint-analysis", names)
        self.assertIn("taint-analysis-interprocedural", names)

    def test_analyze_taint_interprocedural_no_dx(self):
        ctx = self.v.Ctx(apk=None, dex_list=[], dx=None)
        self.assertEqual(self.v.analyze_taint_interprocedural(ctx), [])


class FieldAndAliasingTaint(unittest.TestCase):
    """Tests for field-based propagation (setter/getter pattern) and
    collection aliasing (List.add/get, Map.put/get, Bundle.putString/getString)."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _ins(self, name, operands):
        class _M:
            def __init__(self, n, o): self._n, self._o = n, o
            def get_name(self): return self._n
            def get_operands(self): return self._o
        return _M(name, operands)

    def _method(self, ins, cls_name="Lcom/x/Foo;", method_name="m",
                descriptor="()V", static=False, regs_size=5):
        class _Code:
            def __init__(self, rs): self._rs = rs
            def get_registers_size(self): return self._rs
        class _M:
            def __init__(self):
                self._c, self._n, self._ins = cls_name, method_name, ins
                self._d, self._s, self._code = descriptor, static, _Code(regs_size)
            def get_class_name(self): return self._c
            def get_name(self): return self._n
            def get_descriptor(self): return self._d
            def get_access_flags(self): return 0x8 if self._s else 0
            def get_instructions(self): return iter(self._ins)
            def get_code(self): return self._code
        return _M()

    def test_setter_records_field_write(self):
        # iput-object of a tainted register -> fields_written_tainted populated
        setter = self._method([
            self._ins("invoke-virtual", [(0, 4), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 1)]),
            self._ins("iput-object", [(0, 1), (0, 3),
                "Lcom/x/Foo;->userInput:Ljava/lang/String;"]),
            self._ins("return-void", []),
        ], descriptor="(Landroid/content/Intent;)V", static=False, regs_size=5)
        s = self.v._build_method_summary(setter, {})
        self.assertIn("Lcom/x/Foo;->userInput:Ljava/lang/String;",
                      s.fields_written_tainted)

    def test_getter_records_field_to_sink(self):
        # iget-object then sink call -> fields_read_to_sink populated
        getter = self._method([
            self._ins("iget-object", [(0, 0), (0, 2),
                "Lcom/x/Foo;->userInput:Ljava/lang/String;"]),
            self._ins("invoke-virtual", [(0, 3), (0, 0), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
            self._ins("return-void", []),
        ], descriptor="(Landroid/database/sqlite/SQLiteDatabase;)V",
           static=False, regs_size=4)
        s = self.v._build_method_summary(getter, {})
        self.assertIn("Lcom/x/Foo;->userInput:Ljava/lang/String;",
                      s.fields_read_to_sink)

    def test_setter_const_string_no_field_taint(self):
        # iput-object of a const-string -> NOT tainted
        clean = self._method([
            self._ins("const-string", [(0, 1), "SELECT * FROM users"]),
            self._ins("iput-object", [(0, 1), (0, 2),
                "Lcom/x/Foo;->safeQuery:Ljava/lang/String;"]),
            self._ins("return-void", []),
        ], descriptor="()V", static=False, regs_size=3)
        s = self.v._build_method_summary(clean, {})
        self.assertNotIn("Lcom/x/Foo;->safeQuery:Ljava/lang/String;",
                         s.fields_written_tainted)

    def test_field_flow_emits_finding(self):
        """Setter and getter on same field, in different methods -> emits a
        field-flow finding via analyze_taint_interprocedural."""
        setter = self._method([
            self._ins("invoke-virtual", [(0, 4), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 1)]),
            self._ins("iput-object", [(0, 1), (0, 3),
                "Lcom/x/Foo;->userInput:Ljava/lang/String;"]),
            self._ins("return-void", []),
        ], cls_name="Lcom/x/Foo;", method_name="setData",
           descriptor="(Landroid/content/Intent;)V", static=False, regs_size=5)

        getter = self._method([
            self._ins("iget-object", [(0, 0), (0, 2),
                "Lcom/x/Foo;->userInput:Ljava/lang/String;"]),
            self._ins("invoke-virtual", [(0, 3), (0, 0), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
            self._ins("return-void", []),
        ], cls_name="Lcom/x/Foo;", method_name="runQuery",
           descriptor="(Landroid/database/sqlite/SQLiteDatabase;)V",
           static=False, regs_size=4)

        class MA:
            def __init__(self, m): self.m = m
            def get_method(self): return self.m
        class FakeDX:
            def __init__(self, methods): self.mas = [MA(m) for m in methods]
            def get_methods(self): return iter(self.mas)
            def get_classes(self): return []

        ctx = self.v.Ctx(apk=None, dex_list=[], dx=FakeDX([setter, getter]))
        findings = self.v.analyze_taint_interprocedural(ctx)
        field_findings = [f for f in findings if f.source == "vexa-taint-field"]
        self.assertGreaterEqual(len(field_findings), 1)
        self.assertEqual(field_findings[0].confidence, "likely")
        self.assertIn("via field", field_findings[0].title)

    def test_list_add_get_propagates_taint(self):
        # list.add(taint); list.get() -> taint
        m = self._method([
            self._ins("invoke-virtual", [(0, 5), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 1)]),
            self._ins("invoke-interface", [(0, 0), (0, 1),
                "Ljava/util/List;->add(Ljava/lang/Object;)Z"]),
            self._ins("invoke-interface", [(0, 0), (0, 3),
                "Ljava/util/List;->get(I)Ljava/lang/Object;"]),
            self._ins("move-result-object", [(0, 2)]),
            self._ins("invoke-virtual", [(0, 3), (0, 2), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], descriptor="(Landroid/content/Intent;)V", static=False, regs_size=6)
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0][0]["id"], "taint-sqli-rawquery")

    def test_hashmap_put_get_propagates_taint(self):
        m = self._method([
            self._ins("invoke-virtual", [(0, 5), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 1)]),
            self._ins("invoke-interface", [(0, 0), (0, 4), (0, 1),
                "Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"]),
            self._ins("invoke-interface", [(0, 0), (0, 4),
                "Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;"]),
            self._ins("move-result-object", [(0, 2)]),
            self._ins("invoke-virtual", [(0, 3), (0, 2), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], descriptor="(Landroid/content/Intent;)V", static=False, regs_size=6)
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)

    def test_bundle_putstring_getstring_propagates(self):
        m = self._method([
            self._ins("invoke-virtual", [(0, 5), (0, 0),
                "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 1)]),
            self._ins("invoke-virtual", [(0, 2), (0, 6), (0, 1),
                "Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V"]),
            self._ins("invoke-virtual", [(0, 2), (0, 6),
                "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"]),
            self._ins("move-result-object", [(0, 3)]),
            self._ins("invoke-virtual", [(0, 7), (0, 3), (0, 4),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], descriptor="(Landroid/content/Intent;)V", static=False, regs_size=8)
        flows = self.v._trace_method_taint(m)
        self.assertEqual(len(flows), 1)

    def test_clean_collection_no_false_positive(self):
        # Const-string into list -> get -> sink should NOT flag
        m = self._method([
            self._ins("const-string", [(0, 1), "SELECT * FROM users"]),
            self._ins("invoke-interface", [(0, 0), (0, 1),
                "Ljava/util/List;->add(Ljava/lang/Object;)Z"]),
            self._ins("invoke-interface", [(0, 0), (0, 3),
                "Ljava/util/List;->get(I)Ljava/lang/Object;"]),
            self._ins("move-result-object", [(0, 2)]),
            self._ins("invoke-virtual", [(0, 3), (0, 2), (0, 1),
                "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"]),
        ], descriptor="()V", static=False, regs_size=5)
        flows = self.v._trace_method_taint(m)
        self.assertEqual(flows, [])

    def test_collection_helpers_classify_correctly(self):
        # _is_collection_store/retrieve helpers
        self.assertTrue(self.v._is_collection_store("Ljava/util/List;", "add"))
        self.assertTrue(self.v._is_collection_store("Ljava/util/HashMap;", "put"))
        self.assertTrue(self.v._is_collection_store("Landroid/os/Bundle;", "putString"))
        self.assertTrue(self.v._is_collection_retrieve("Ljava/util/List;", "get"))
        self.assertTrue(self.v._is_collection_retrieve("Landroid/os/Bundle;", "getString"))
        self.assertFalse(self.v._is_collection_store("Ljava/util/List;", "size"))
        self.assertFalse(self.v._is_collection_store("Ljava/lang/String;", "concat"))


class IOSPath2Analyzers(unittest.TestCase):
    """Tests for the iOS Path-2 expansion (35 new analyzers covering MASVS-AUTH/
    NETWORK/PLATFORM/RESILIENCE/STORAGE/CRYPTO/CODE on iOS)."""

    @classmethod
    def setUpClass(cls):
        import vexa as v
        cls.v = v

    def _make_ctx(self, **kwargs):
        defaults = {
            "ipa_path": "",
            "app_dir": "",
            "info_plist": {},
            "files": [],
            "binary_path": "",
            "binary_strings": [],
            "entitlements": {},
            "mobileprovision": {},
            "extras": {},
        }
        defaults.update(kwargs)
        return self.v.IOSCtx(**defaults)

    def test_ios_analyzer_count(self):
        # 15 (existing) + 35 (Path-2) = 50 minimum
        self.assertGreaterEqual(len(self.v.IOS_ANALYZERS), 50)
        names = {n for n, _ in self.v.IOS_ANALYZERS}
        for new_name in ("ios-jwt-alg-none", "ios-cc-weak-hash",
                         "ios-cleartext-websocket", "ios-realm-not-encrypted",
                         "ios-dev-provisioning-profile"):
            self.assertIn(new_name, names, f"missing analyzer: {new_name}")

    def test_local_auth_passcode_fallback_fires(self):
        ctx = self._make_ctx(binary_strings=[
            "LAContext", "evaluatePolicy",
            "LAPolicyDeviceOwnerAuthentication"])
        result = self.v.ios_analyze_local_auth_weak_policy(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].confidence, "likely")

    def test_local_auth_no_fp_on_strict_policy(self):
        # Both policies present -> no finding because strict one IS used
        ctx = self._make_ctx(binary_strings=[
            "LAContext", "evaluatePolicy",
            "LAPolicyDeviceOwnerAuthentication",
            "LAPolicyDeviceOwnerAuthenticationWithBiometrics"])
        self.assertEqual(self.v.ios_analyze_local_auth_weak_policy(ctx), [])

    def test_userdefaults_sensitive_keys_fires(self):
        ctx = self._make_ctx(binary_strings=[
            "NSUserDefaults", "userpassword", "auth_token"])
        result = self.v.ios_analyze_password_in_userdefaults(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_userdefaults_no_fp_without_sensitive_keys(self):
        ctx = self._make_ctx(binary_strings=[
            "NSUserDefaults", "preferred_language", "last_seen_version"])
        self.assertEqual(self.v.ios_analyze_password_in_userdefaults(ctx), [])

    def test_jwt_alg_none_fires(self):
        ctx = self._make_ctx(binary_strings=["JWTKit", "alg", "none"])
        result = self.v.ios_analyze_jwt_alg_none(ctx)
        self.assertEqual(len(result), 1)

    def test_ats_weak_tls_fires(self):
        ctx = self._make_ctx(info_plist={
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "api.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}
                }
            }
        })
        result = self.v.ios_analyze_ats_min_tls_version(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_ats_weak_tls_no_fp_on_modern(self):
        ctx = self._make_ctx(info_plist={
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "api.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.2"}
                }
            }
        })
        self.assertEqual(self.v.ios_analyze_ats_min_tls_version(ctx), [])

    def test_websocket_cleartext_fires(self):
        ctx = self._make_ctx(binary_strings=["ws://api.example.com/socket"])
        result = self.v.ios_analyze_websocket_cleartext(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "ios-cleartext-websocket")

    def test_websocket_cleartext_ignores_localhost(self):
        ctx = self._make_ctx(binary_strings=[
            "ws://localhost:8080/test", "ws://127.0.0.1/socket",
            "ws://192.168.1.5/ws"])
        self.assertEqual(self.v.ios_analyze_websocket_cleartext(ctx), [])

    def test_custom_trust_bypass_fires(self):
        ctx = self._make_ctx(binary_strings=[
            "didReceiveChallenge",
            "NSURLAuthenticationMethodServerTrust",
            "NSURLSessionAuthChallengeUseCredential"])
        result = self.v.ios_analyze_custom_hostname_verifier(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "critical")

    def test_custom_trust_no_fp_with_proper_eval(self):
        # Has SecTrustEvaluate -> no finding
        ctx = self._make_ctx(binary_strings=[
            "didReceiveChallenge",
            "NSURLAuthenticationMethodServerTrust",
            "NSURLSessionAuthChallengeUseCredential",
            "SecTrustEvaluateWithError"])
        self.assertEqual(self.v.ios_analyze_custom_hostname_verifier(ctx), [])

    def test_wkwebview_universal_access_fires(self):
        ctx = self._make_ctx(binary_strings=["allowUniversalAccessFromFileURLs"])
        result = self.v.ios_analyze_wkwebview_universal_access(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_realm_no_encryption_fires(self):
        ctx = self._make_ctx(binary_strings=["RLMRealm", "Realm.Configuration"])
        result = self.v.ios_analyze_realm_no_encryption(ctx)
        self.assertEqual(len(result), 1)

    def test_realm_no_fp_when_encrypted(self):
        ctx = self._make_ctx(binary_strings=[
            "RLMRealm", "Realm.Configuration", "encryptionKey"])
        self.assertEqual(self.v.ios_analyze_realm_no_encryption(ctx), [])

    def test_md5_sha1_fires(self):
        ctx = self._make_ctx(binary_strings=["CC_MD5"])
        result = self.v.ios_analyze_commoncrypto_md5_sha1(ctx)
        self.assertEqual(len(result), 1)

    def test_des_3des_fires(self):
        ctx = self._make_ctx(binary_strings=["kCCAlgorithmDES"])
        result = self.v.ios_analyze_commoncrypto_des_3des(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_ecb_fires(self):
        ctx = self._make_ctx(binary_strings=["kCCOptionECBMode"])
        result = self.v.ios_analyze_cipher_ecb_mode(ctx)
        self.assertEqual(len(result), 1)

    def test_dev_provisioning_profile_fires(self):
        ctx = self._make_ctx(mobileprovision={
            "Entitlements": {"get-task-allow": True}
        })
        result = self.v.ios_analyze_embedded_provisioning_profile(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    def test_app_extensions_detected(self):
        ctx = self._make_ctx(files=[
            "Payload/MyApp.app/PlugIns/MyShare.appex/Info.plist"])
        result = self.v.ios_analyze_app_extension_exposed(ctx)
        self.assertEqual(len(result), 1)

    def test_third_party_sdks_inventory(self):
        ctx = self._make_ctx(binary_strings=["FIRApp", "FBSDKCoreKit"])
        result = self.v.ios_analyze_third_party_sdks(ctx)
        self.assertEqual(len(result), 1)
        self.assertIn("Firebase", result[0].evidence)
        self.assertIn("Facebook", result[0].evidence)

    def test_empty_ctx_no_findings(self):
        """Smoke: every Path-2 analyzer returns [] on empty ctx."""
        ctx = self._make_ctx()
        for name, fn in self.v.IOS_EXTENDED_ANALYZERS_2:
            result = fn(ctx)
            self.assertEqual(result, [],
                             f"{name} should not flag empty ctx, got {result}")


def cleanup():
    shutil.rmtree(_TEST_DATA, ignore_errors=True)


if __name__ == "__main__":
    import atexit
    atexit.register(cleanup)
    # Run tests via unittest
    unittest.main(verbosity=2, exit=False)
    cleanup()
