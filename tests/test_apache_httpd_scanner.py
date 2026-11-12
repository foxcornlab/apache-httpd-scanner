#!/usr/bin/env python3
"""Tests for apache_httpd_scanner.py.

Covers version parsing in every accepted form, the grading
boundaries for all three CVEs in the 2.4.71 batch, the module
exposure rules, the distro-backport trap, the standalone mod_h2
trap, local detection against a fake httpd binary, remote probing
against a mock HTTP server, CLI exit codes, JSON output, and
fleet inventory grading.
"""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import apache_httpd_scanner as scanner

C119 = scanner.CVE_119618
C023 = scanner.CVE_106023
C163 = scanner.CVE_109163


class ParseVersionTests(unittest.TestCase):
    def test_bare_version(self):
        self.assertEqual(
            scanner.parse_version("2.4.63"), ((2, 4, 63), False, "2.4.63")
        )

    def test_server_version_line(self):
        version, distro, _raw = scanner.parse_version(
            "Server version: Apache/2.4.63 (Unix)"
        )
        self.assertEqual(version, (2, 4, 63))
        self.assertFalse(distro)

    def test_debian_build_is_distro(self):
        version, distro, _raw = scanner.parse_version(
            "Server version: Apache/2.4.62 (Debian)"
        )
        self.assertEqual(version, (2, 4, 62))
        self.assertTrue(distro)

    def test_ubuntu_build_is_distro(self):
        _version, distro, _raw = scanner.parse_version(
            "Apache/2.4.52 (Ubuntu)"
        )
        self.assertTrue(distro)

    def test_red_hat_build_is_distro(self):
        _version, distro, _raw = scanner.parse_version(
            "Server version: Apache/2.4.62 (Red Hat Enterprise Linux)"
        )
        self.assertTrue(distro)

    def test_win64_upstream_is_not_distro(self):
        _version, distro, _raw = scanner.parse_version(
            "Apache/2.4.63 (Win64)"
        )
        self.assertFalse(distro)

    def test_v_prefix(self):
        version, _distro, _raw = scanner.parse_version("v2.4.71")
        self.assertEqual(version, (2, 4, 71))

    def test_bare_major_minor_does_not_parse(self):
        self.assertIsNone(scanner.parse_version("2.4"))

    def test_masked_server_header_does_not_parse(self):
        self.assertIsNone(scanner.parse_version("Apache"))

    def test_garbage_does_not_parse(self):
        self.assertIsNone(scanner.parse_version("not a version"))


class Grade119618Tests(unittest.TestCase):
    def grade(self, version, **kwargs):
        return scanner.grade(version, **kwargs)["cves"][C119]

    def test_below_range_not_affected(self):
        self.assertEqual(self.grade("2.4.54")["grade"], "NOT-AFFECTED")

    def test_range_start_vulnerable(self):
        self.assertEqual(self.grade("2.4.55")["grade"], "VULNERABLE")

    def test_range_end_vulnerable(self):
        self.assertEqual(self.grade("2.4.70")["grade"], "VULNERABLE")

    def test_fixed_release_patched(self):
        self.assertEqual(self.grade("2.4.71")["grade"], "PATCHED")

    def test_later_release_patched(self):
        self.assertEqual(self.grade("2.4.72")["grade"], "PATCHED")

    def test_http2_off_not_exposed(self):
        result = scanner.grade("2.4.63", exposure={"http2": False})
        self.assertEqual(result["cves"][C119]["grade"], "NOT-EXPOSED")
        # The other two CVEs are still graded on their own modules.
        self.assertEqual(result["cves"][C023]["grade"], "VULNERABLE")
        self.assertEqual(result["overall"], "VULNERABLE")

    def test_unknown_exposure_assumed_loaded(self):
        result = self.grade("2.4.63")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("assumes it is loaded", result["note"])


class Grade106023Tests(unittest.TestCase):
    def grade(self, version, **kwargs):
        return scanner.grade(version, **kwargs)["cves"][C023]

    def test_below_range_not_affected(self):
        self.assertEqual(self.grade("2.4.29")["grade"], "NOT-AFFECTED")

    def test_range_start_vulnerable(self):
        self.assertEqual(self.grade("2.4.30")["grade"], "VULNERABLE")

    def test_fixed_release_patched(self):
        self.assertEqual(self.grade("2.4.71")["grade"], "PATCHED")

    def test_mod_md_off_not_exposed(self):
        result = scanner.grade("2.4.63", exposure={"mod_md": False})
        self.assertEqual(result["cves"][C023]["grade"], "NOT-EXPOSED")


class Grade109163Tests(unittest.TestCase):
    def grade(self, version, **kwargs):
        return scanner.grade(version, **kwargs)["cves"][C163]

    def test_below_range_not_affected(self):
        self.assertEqual(self.grade("2.4.68")["grade"], "NOT-AFFECTED")

    def test_range_start_vulnerable(self):
        self.assertEqual(self.grade("2.4.69")["grade"], "VULNERABLE")

    def test_range_end_vulnerable(self):
        self.assertEqual(self.grade("2.4.70")["grade"], "VULNERABLE")

    def test_fixed_release_patched(self):
        self.assertEqual(self.grade("2.4.71")["grade"], "PATCHED")

    def test_vhost_alias_off_not_exposed(self):
        result = scanner.grade(
            "2.4.70", exposure={"mod_vhost_alias": False}
        )
        self.assertEqual(result["cves"][C163]["grade"], "NOT-EXPOSED")


class OverallAndTrapTests(unittest.TestCase):
    def test_all_patched_overall(self):
        result = scanner.grade("2.4.71")
        self.assertEqual(result["overall"], "PATCHED")

    def test_all_not_affected_overall(self):
        # 2.4.0 is below every affected range in the batch.
        result = scanner.grade("2.4.0")
        self.assertEqual(result["overall"], "NOT-AFFECTED")

    def test_distro_build_is_unknown(self):
        result = scanner.grade("Server version: Apache/2.4.62 (Debian)")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertIn("backport", result["cves"][C119]["note"])

    def test_assume_upstream_grades_distro_string(self):
        result = scanner.grade(
            "Server version: Apache/2.4.62 (Debian)", assume_upstream=True
        )
        self.assertEqual(result["overall"], "VULNERABLE")

    def test_2_2_line_is_unknown(self):
        result = scanner.grade("2.2.34")
        self.assertEqual(result["overall"], "UNKNOWN")

    def test_unparseable_is_unknown(self):
        result = scanner.grade("Apache")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertIn("ServerTokens", result["cves"][C119]["note"])


class ModH2Tests(unittest.TestCase):
    def test_below_range_not_affected(self):
        self.assertEqual(
            scanner.grade_mod_h2("2.0.7")["grade"], "NOT-AFFECTED"
        )

    def test_range_start_vulnerable(self):
        self.assertEqual(
            scanner.grade_mod_h2("2.0.8")["grade"], "VULNERABLE"
        )

    def test_latest_release_still_vulnerable(self):
        # The trap: 2.0.42 is the latest mod_h2 release and it is
        # still vulnerable, there is no fixed release yet.
        result = scanner.grade_mod_h2("2.0.42")
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("no fixed mod_h2 release", result["note"].lower())

    def test_above_latest_is_unknown(self):
        result = scanner.grade_mod_h2("2.0.43")
        self.assertEqual(result["grade"], "UNKNOWN")

    def test_garbage_is_unknown(self):
        self.assertEqual(
            scanner.grade_mod_h2("nope")["grade"], "UNKNOWN"
        )


def _make_handler(server_value, send_server=True):
    class Handler(BaseHTTPRequestHandler):
        def version_string(self):
            return server_value

        def send_response(self, code, message=None):
            if send_server:
                super().send_response(code, message)
            else:
                self.send_response_only(code, message)
                self.send_header("Date", self.date_time_string())

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


def _run_mock_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class ProbeUrlTests(unittest.TestCase):
    def test_vulnerable_server_header(self):
        server, url = _run_mock_server(_make_handler("Apache/2.4.63 (Unix)"))
        try:
            result, notes = scanner.probe_url(url)
        finally:
            server.shutdown()
        self.assertEqual(result["overall"], "VULNERABLE")
        self.assertEqual(result["cves"][C119]["grade"], "VULNERABLE")
        self.assertTrue(any("plain HTTP" in note for note in notes))

    def test_patched_server_header(self):
        server, url = _run_mock_server(_make_handler("Apache/2.4.71 (Unix)"))
        try:
            result, _notes = scanner.probe_url(url)
        finally:
            server.shutdown()
        self.assertEqual(result["overall"], "PATCHED")

    def test_masked_server_header_is_unknown(self):
        server, url = _run_mock_server(_make_handler("Apache"))
        try:
            result, _notes = scanner.probe_url(url)
        finally:
            server.shutdown()
        self.assertEqual(result["overall"], "UNKNOWN")

    def test_no_server_header_is_an_error(self):
        server, url = _run_mock_server(
            _make_handler("Apache/2.4.63 (Unix)", send_server=False)
        )
        try:
            with self.assertRaises(RuntimeError):
                scanner.probe_url(url)
        finally:
            server.shutdown()

    def test_bad_scheme_is_an_error(self):
        with self.assertRaises(ValueError):
            scanner.probe_url("ftp://example.com")


class FakeHttpdTests(unittest.TestCase):
    """Local detection against a fake httpd binary on PATH."""

    FAKE_SCRIPT = """#!/bin/sh
if [ "$1" = "-v" ]; then
  echo "Server version: {version}"
  echo "Server built:   Nov 11 2026 00:00:00"
elif [ "$1" = "-M" ]; then
  echo "Loaded Modules:"
  echo " http2_module (shared)"
  echo " md_module (shared)"
  echo " vhost_alias_module (shared)"
elif [ "$1" = "-V" ]; then
  echo "Server version: {version}"
  echo '  -D HTTPD_ROOT="/etc/apache2"'
  echo '  -D SERVER_CONFIG_FILE="{config}"'
fi
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bindir = Path(self.tmp.name) / "bin"
        self.bindir.mkdir()
        self.config = Path(self.tmp.name) / "httpd.conf"
        self.config.write_text("Protocols h2 http/1.1\n")
        self._write_fake("Server version: Apache/2.4.63 (Unix)")
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.bindir}:{self.old_path}"

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        self.tmp.cleanup()

    def _write_fake(self, version_line):
        script = self.bindir / "httpd"
        script.write_text(
            self.FAKE_SCRIPT.format(
                version=version_line, config=self.config
            )
        )
        script.chmod(0o755)

    def test_detect_local_vulnerable(self):
        version, exposure, notes = scanner.detect_local()
        self.assertIn("2.4.63", version)
        self.assertTrue(exposure["http2"])
        self.assertTrue(exposure["mod_md"])
        self.assertTrue(exposure["mod_vhost_alias"])
        result = scanner.grade(version, exposure=exposure)
        self.assertEqual(result["overall"], "VULNERABLE")

    def test_detect_local_distro_build(self):
        self._write_fake("Server version: Apache/2.4.62 (Debian)")
        version, exposure, notes = scanner.detect_local()
        result = scanner.grade(version, exposure=exposure)
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertTrue(any("distribution build" in n for n in notes))

    def test_detect_local_h2_off_in_config(self):
        self.config.write_text("Protocols http/1.1\n")
        version, exposure, notes = scanner.detect_local()
        self.assertFalse(exposure["http2"])
        result = scanner.grade(version, exposure=exposure)
        self.assertEqual(result["cves"][C119]["grade"], "NOT-EXPOSED")


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = scanner.main(argv)
        return code, buffer.getvalue()

    def test_version_vulnerable_exit_2(self):
        code, out = self.run_main(["--version", "2.4.63"])
        self.assertEqual(code, 2)
        self.assertIn("VULNERABLE", out)

    def test_version_patched_exit_0(self):
        code, out = self.run_main(["--version", "2.4.71"])
        self.assertEqual(code, 0)
        self.assertIn("PATCHED", out)

    def test_mod_h2_vulnerable_exit_2(self):
        code, out = self.run_main(["--mod-h2-version", "2.0.42"])
        self.assertEqual(code, 2)
        self.assertIn("VULNERABLE", out)

    def test_mod_h2_patched_exit_0(self):
        code, out = self.run_main(["--mod-h2-version", "2.0.7"])
        self.assertEqual(code, 0)

    def test_json_output(self):
        code, out = self.run_main(["--version", "2.4.63", "--json"])
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data["overall"], "VULNERABLE")
        self.assertEqual(data["cves"][C119]["grade"], "VULNERABLE")

    def test_list_contains_all_cves(self):
        code, out = self.run_main(["--list"])
        self.assertEqual(code, 0)
        for cve in (C119, C023, C163):
            self.assertIn(cve, out)

    def test_version_file(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False
        ) as handle:
            handle.write("Server version: Apache/2.4.70 (Unix)\n")
            path = handle.name
        try:
            code, out = self.run_main(["--version-file", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 2)

    def test_inventory_json(self):
        entries = [
            {"label": "web-01", "version": "2.4.63"},
            {"label": "web-02", "version": "2.4.71"},
            {"label": "web-03", "version": "Apache"},
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump(entries, handle)
            path = handle.name
        try:
            code, out = self.run_main(["--inventory-json", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 2)
        self.assertIn("[web-01]", out)
        self.assertIn("VULNERABLE", out)
        self.assertIn("[web-02]", out)
        self.assertIn("PATCHED", out)

    def test_inventory_json_all_patched_exit_0(self):
        entries = [{"label": "web-02", "version": "2.4.71"}]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump(entries, handle)
            path = handle.name
        try:
            code, _out = self.run_main(["--inventory-json", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)

    def test_missing_file_is_error(self):
        code, _out = self.run_main(["--version-file", "/nonexistent/x.txt"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
