#!/usr/bin/env python3
"""Detection-only triage for the Apache HTTP Server 2.4.71 batch.

On 11 November 2026 the Apache HTTP Server project released httpd
2.4.71, a security release fixing three CVEs:

    CVE-2026-119618 (critical, Red Hat CVSS 3.1 9.8): mod_http2 heap
        corruption and RCE in assign_headers(). A race on shared
        request headers corrupts the heap when an HTTP/2 request
        carries a Content-Type header and ends immediately with
        END_STREAM and no Content-Length. Affects httpd 2.4.55
        through 2.4.70 and the standalone mod_h2 module from GitHub
        2.0.8 through 2.0.42. No exploitation in the wild or public
        exploit code has been reported as of 11 November 2026.
    CVE-2026-106023 (important): mod_md NULL pointer dereference
        during HTTP request processing. Affects httpd 2.4.30
        through 2.4.70. A child-process crash, not RCE.
    CVE-2026-109163 (low): mod_vhost_alias one-byte stack buffer
        overwrite, a follow-on to CVE-2026-63292. Affects httpd
        2.4.69 and 2.4.70 only.

The traps this tool exists for: a version number alone does not prove
patch status on a distribution build. Debian, Ubuntu, RHEL and other
distros backport security fixes into their own httpd packages while
keeping the upstream version number, so `2.4.52` on Ubuntu may already
carry the fix, or may not, and this tool cannot tell from the string.
A distro build grades UNKNOWN, not clean, and the note tells you to
check your vendor tracker (Debian DSA, Ubuntu USN, RHSA). The second
trap is the standalone mod_h2: version 2.0.42 is the latest release
and it is still vulnerable, there is no fixed mod_h2 release yet, so
anything from 2.0.8 through 2.0.42 grades VULNERABLE. The third trap
is exposure: CVE-2026-119618 only bites when mod_http2 is loaded and
HTTP/2 is on, CVE-2026-106023 only when mod_md is loaded, and
CVE-2026-109163 only when mod_vhost_alias is loaded. A version in
range with the module off grades NOT-EXPOSED, not VULNERABLE.

This tool sends no payloads and runs no exploit. `--url` makes one
plain HEAD request to read the Server header and, over TLS, one
handshake offering ALPN `h2` to see whether the server negotiates
HTTP/2. It never sends an HTTP/2 preface or a crafted request. A
VULNERABLE grade means the version is below the fix; it does not mean
the server was compromised, and a PATCHED grade does not prove it was
never attacked.

Usage:
    python3 apache_httpd_scanner.py --version 2.4.63
    python3 apache_httpd_scanner.py --version "Server version: Apache/2.4.63 (Debian)"
    python3 apache_httpd_scanner.py --local
    python3 apache_httpd_scanner.py --url https://example.com
    python3 apache_httpd_scanner.py --mod-h2-version 2.0.42
    python3 apache_httpd_scanner.py --version-file version.txt
    python3 apache_httpd_scanner.py --inventory-json sites.json
    python3 apache_httpd_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input). UNKNOWN does not change
the exit code, but it is not clean: an unparseable, masked, or
distro-built version has not been cleared, it has simply not been
graded.
"""

import argparse
import http.client
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
from pathlib import Path

CVE_119618 = "CVE-2026-119618"
CVE_106023 = "CVE-2026-106023"
CVE_109163 = "CVE-2026-109163"
FIXED = (2, 4, 71)

# Affected ranges, per the Apache HTTP Server 2.4 vulnerabilities page
# (read 12 November 2026), corroborated by the 2.4.71 release notes.
RANGE_119618 = ((2, 4, 55), (2, 4, 70))
RANGE_106023 = ((2, 4, 30), (2, 4, 70))
RANGE_109163 = ((2, 4, 69), (2, 4, 70))
# Standalone mod_h2 from GitHub (icing/mod_h2). No fixed release exists
# yet: 2.0.42 is the latest and is still vulnerable.
MOD_H2_RANGE = ((2, 0, 8), (2, 0, 42))

# Markers that say "this is a distribution build, not an upstream
# release". A distro build may already carry a backported fix under
# the same upstream version number, so the version alone cannot grade
# it. "(Unix)" and "(Win64)" are upstream builds and are not markers.
_DISTRO_MARKERS = (
    "(Debian)",
    "(Ubuntu)",
    "(Red Hat",
    "(CentOS",
    "(Fedora)",
    "(Rocky",
    "(AlmaLinux",
    "(Oracle Linux",
    "(SUSE",
    "(openSUSE",
)
_DISTRO_SUFFIX_RE = re.compile(
    r"(?:-1ubuntu|ubuntu\d|\.el\d|\.fc\d|\+deb\d|\.deb\d|_deb\d)",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text):
    """Return (version_tuple, distro_build, raw) or None.

    Accepts a bare version like `2.4.63`, an `httpd -v` line like
    `Server version: Apache/2.4.63 (Debian)`, or a Server header value
    like `Apache/2.4.63 (Unix)`. A version with no patch number, such
    as a bare `2.4`, cannot be graded and returns None.
    """
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    version = tuple(int(part) for part in match.groups())
    distro = any(marker in text for marker in _DISTRO_MARKERS) or bool(
        _DISTRO_SUFFIX_RE.search(text)
    )
    return version, distro, text.strip()


def format_version(version):
    return ".".join(str(part) for part in version)


def _grade_one(version, lo, hi, cve, module, exposure):
    """Grade one CVE against one version tuple.

    exposure is True (module loaded / HTTP/2 on), False (module not
    loaded), or None (unknown, assumed exposed, and the note says so).
    """
    if version < lo:
        return {
            "grade": "NOT-AFFECTED",
            "fixed": format_version(FIXED),
            "note": f"httpd {format_version(version)} is below the "
            f"affected range for {cve} "
            f"({format_version(lo)} through {format_version(hi)}), so "
            "this flaw does not apply to it",
        }
    if version >= FIXED:
        return {
            "grade": "PATCHED",
            "fixed": format_version(FIXED),
            "note": f"httpd {format_version(version)} is at or above "
            f"the fixed release {format_version(FIXED)}",
        }
    if exposure is False:
        return {
            "grade": "NOT-EXPOSED",
            "fixed": format_version(FIXED),
            "note": f"httpd {format_version(version)} is in the "
            f"affected range for {cve}, but {module} is not loaded, "
            "so the vulnerable code is not reachable on this install",
        }
    note = (
        f"httpd {format_version(version)} is in the affected range "
        f"for {cve} ({format_version(lo)} through "
        f"{format_version(hi)}); upgrade to "
        f"{format_version(FIXED)} or later"
    )
    if exposure is None:
        note += (
            f". {module} status is unknown, so this grade assumes it "
            "is loaded; confirm with `apachectl -M` if you need the "
            "exposure narrowed"
        )
    return {"grade": "VULNERABLE", "fixed": format_version(FIXED), "note": note}


def grade(version_text, exposure=None, assume_upstream=False):
    """Grade one httpd version string against the whole 2.4.71 batch.

    exposure is a dict with optional boolean keys `http2`, `mod_md`,
    `mod_vhost_alias`. A missing key means unknown, assumed exposed.
    Returns a dict with per-CVE grades and an overall verdict.
    """
    exposure = exposure or {}
    parsed = parse_version(version_text)
    if parsed is None:
        return {
            "version": version_text,
            "overall": "UNKNOWN",
            "cves": {
                cve: {
                    "grade": "UNKNOWN",
                    "fixed": format_version(FIXED),
                    "note": f"version {version_text!r} does not parse "
                    "as an httpd release like 2.4.63. A bare `Apache` "
                    "with no version, which is what ServerTokens Prod "
                    "sends, cannot be graded, and is not clean",
                }
                for cve in (CVE_119618, CVE_106023, CVE_109163)
            },
        }
    version, distro, _raw = parsed
    if distro and not assume_upstream:
        note = (
            f"httpd {format_version(version)} is a distribution build; "
            "distros backport security fixes under the same upstream "
            "version number, so this string cannot prove whether the "
            "fix is in. Check your vendor tracker (Debian DSA, Ubuntu "
            "USN, RHSA) for CVE-2026-119618 and do not treat it as safe"
        )
        return {
            "version": format_version(version),
            "overall": "UNKNOWN",
            "cves": {
                cve: {
                    "grade": "UNKNOWN",
                    "fixed": format_version(FIXED),
                    "note": note,
                }
                for cve in (CVE_119618, CVE_106023, CVE_109163)
            },
        }
    if version[0] != 2 or version[1] != 4:
        note = (
            f"httpd {format_version(version)} is not a 2.4 release. "
            "This tool grades the 2.4 line only; the 2.2 line is end "
            "of life and 2.5/3.0 do not exist yet. It has not been "
            "cleared, only left ungraded"
        )
        return {
            "version": format_version(version),
            "overall": "UNKNOWN",
            "cves": {
                cve: {
                    "grade": "UNKNOWN",
                    "fixed": format_version(FIXED),
                    "note": note,
                }
                for cve in (CVE_119618, CVE_106023, CVE_109163)
            },
        }
    cves = {
        CVE_119618: _grade_one(
            version, *RANGE_119618, CVE_119618, "mod_http2 with HTTP/2 on",
            exposure.get("http2"),
        ),
        CVE_106023: _grade_one(
            version, *RANGE_106023, CVE_106023, "mod_md",
            exposure.get("mod_md"),
        ),
        CVE_109163: _grade_one(
            version, *RANGE_109163, CVE_109163, "mod_vhost_alias",
            exposure.get("mod_vhost_alias"),
        ),
    }
    order = ["VULNERABLE", "UNKNOWN", "NOT-EXPOSED", "PATCHED", "NOT-AFFECTED"]
    overall = min(
        (result["grade"] for result in cves.values()),
        key=order.index,
    )
    return {"version": format_version(version), "overall": overall, "cves": cves}


def grade_mod_h2(version_text):
    """Grade a standalone mod_h2 version from GitHub (icing/mod_h2).

    There is no fixed release yet: 2.0.42 is the latest and is still
    vulnerable, so anything in range grades VULNERABLE and anything
    above the range grades UNKNOWN until upstream ships a fix.
    """
    parsed = parse_version(version_text)
    if parsed is None:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"mod_h2 version {version_text!r} does not parse "
            "as a release like 2.0.42",
        }
    version, _distro, _raw = parsed
    lo, hi = MOD_H2_RANGE
    if version < lo:
        return {
            "grade": "NOT-AFFECTED",
            "fixed": None,
            "note": f"mod_h2 {format_version(version)} is below the "
            f"affected range ({format_version(lo)} through "
            f"{format_version(hi)})",
        }
    if version <= hi:
        return {
            "grade": "VULNERABLE",
            "fixed": None,
            "note": f"mod_h2 {format_version(version)} is in the "
            f"affected range ({format_version(lo)} through "
            f"{format_version(hi)}). There is no fixed mod_h2 release "
            "yet, 2.0.42 is the latest and is still vulnerable; do not "
            "go back to the standalone module, use the httpd 2.4.71 "
            "bundled mod_http2 instead",
        }
    return {
        "grade": "UNKNOWN",
        "fixed": None,
        "note": f"mod_h2 {format_version(version)} is above 2.0.42, "
        "the latest release at the time of writing. No fixed release "
        "has been published yet, so verify against the upstream "
        "icing/mod_h2 releases before trusting it",
    }


_BINARIES = ("httpd", "apache2", "apachectl")


def _run(cmd, timeout=10):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return proc.stdout + proc.stderr


def _find_binary():
    for name in _BINARIES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _parse_modules(output):
    """Parse `apachectl -M` output into a set of loaded module names."""
    if not output:
        return None
    modules = set()
    for line in output.splitlines():
        match = re.search(r"(\w+)_module\s+\(", line)
        if match:
            modules.add(match.group(1))
    return modules if modules else None


def _read_config_tree(main_config):
    """Read a httpd config file plus one level of Include lines."""
    text = ""
    try:
        text = Path(main_config).read_text(errors="ignore")
    except OSError:
        return ""
    base = Path(main_config).parent
    for match in re.finditer(r"(?im)^\s*Include(?:Optional)?\s+(\S+)", text):
        pattern = match.group(1)
        candidates = []
        if Path(pattern).is_absolute():
            candidates = [Path(pattern)]
        else:
            candidates = list(base.glob(pattern))
        for candidate in candidates:
            if candidate.is_file():
                try:
                    text += "\n" + candidate.read_text(errors="ignore")
                except OSError:
                    continue
    return text


def detect_local():
    """Detect a local httpd install: version, modules, HTTP/2 status.

    Returns (version_text, exposure_dict, notes). Version comes from
    `httpd -v` / `apache2 -v` / `apachectl -v`; exposure comes from
    `-M` module output and the Protocols lines in the config. A
    distro package version found via dpkg/rpm is reported in the
    notes and forces the distro-build UNKNOWN grade.
    """
    binary = _find_binary()
    if not binary:
        raise RuntimeError(
            "no httpd, apache2 or apachectl binary found on PATH; "
            "pass --version instead"
        )
    version_out = _run([binary, "-v"])
    if not version_out:
        raise RuntimeError(f"{binary} -v produced no output")
    version_text = None
    for line in version_out.splitlines():
        if "Server version" in line:
            version_text = line.split(":", 1)[1].strip()
            break
    if version_text is None:
        version_text = version_out.strip().splitlines()[0]
    notes = []
    parsed = parse_version(version_text)
    if parsed and parsed[1]:
        notes.append(
            f"{binary} -v reports a distribution build "
            f"({version_text}); it grades UNKNOWN unless "
            "--assume-upstream is given"
        )
    modules_out = _run([binary, "-M"])
    modules = _parse_modules(modules_out)
    exposure = {}
    if modules is None:
        notes.append(f"could not list loaded modules via {binary} -M")
    else:
        exposure["http2"] = "http2" in modules
        exposure["mod_md"] = "md" in modules
        exposure["mod_vhost_alias"] = "vhost_alias" in modules
    config_out = _run([binary, "-V"])
    main_config = None
    if config_out:
        match = re.search(r'SERVER_CONFIG_FILE="([^"]+)"', config_out)
        if match:
            main_config = match.group(1)
    if main_config:
        config_text = _read_config_tree(main_config)
        protocols = re.findall(
            r"(?im)^\s*Protocols(?:HonorOrder)?\s+(.+)$", config_text
        )
        if protocols:
            h2_on = any("h2" in line.split() for line in protocols)
            if exposure.get("http2") is False:
                notes.append(
                    "mod_http2 is not loaded, so Protocols lines "
                    "cannot enable HTTP/2"
                )
            elif not h2_on:
                exposure["http2"] = False
                notes.append(
                    "Protocols lines found but none enables h2, so "
                    "HTTP/2 is off on this install"
                )
            else:
                notes.append("Protocols lines enable h2")
    else:
        notes.append("could not locate the main config file via -V")
    return version_text, exposure, notes


def probe_url(url):
    """Grade a remote httpd from its Server header and ALPN, read-only.

    One HEAD request reads the Server header; over TLS the handshake
    offers ALPN `h2` to learn whether the server negotiates HTTP/2.
    No HTTP/2 preface and no crafted request is ever sent. Returns
    (result_dict, notes).
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {url!r}")
    if not parsed_url.hostname:
        raise ValueError(f"URL has no host: {url!r}")
    host = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    path = parsed_url.path or "/"
    notes = []
    server_header = None
    alpn = None
    if parsed_url.scheme == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        raw = socket.create_connection((host, port), timeout=10)
        try:
            tls = context.wrap_socket(raw, server_hostname=host)
            alpn = tls.selected_alpn_protocol()
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.sock = tls
            conn.request("HEAD", path)
            response = conn.getresponse()
            server_header = response.getheader("Server")
            response.read()
            conn.close()
        finally:
            raw.close()
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("HEAD", path)
        response = conn.getresponse()
        server_header = response.getheader("Server")
        response.read()
        conn.close()
        notes.append(
            "plain HTTP cannot confirm HTTP/2 support without sending "
            "an HTTP/2 preface, which this tool never does; h2 status "
            "is unknown unless you confirm Protocols in the config"
        )
    if alpn is not None:
        notes.append(
            f"TLS ALPN negotiated {alpn!r}; "
            f"HTTP/2 is {'on' if alpn == 'h2' else 'off'} on this server"
        )
    if not server_header:
        raise RuntimeError(
            "no Server header returned; the version is masked and "
            "cannot be graded from the network"
        )
    exposure = {}
    if alpn is not None:
        exposure["http2"] = alpn == "h2"
    result = grade(server_header, exposure=exposure)
    return result, notes


def grade_inventory(entries):
    """Grade a fleet inventory: list of {label, version, ...} dicts."""
    results = []
    for entry in entries:
        label = entry.get("label", entry.get("host", "?"))
        version = entry.get("version")
        if version is None:
            results.append(
                {
                    "label": label,
                    "overall": "UNKNOWN",
                    "note": "no version in this inventory entry",
                }
            )
            continue
        exposure = {
            key: entry[key]
            for key in ("http2", "mod_md", "mod_vhost_alias")
            if key in entry
        }
        result = grade(
            version,
            exposure=exposure,
            assume_upstream=bool(entry.get("assume_upstream")),
        )
        result["label"] = label
        results.append(result)
    return results


def print_table():
    print("Apache HTTP Server 2.4.71 batch, released 11 November 2026")
    print()
    print("CVE              Score  Affected httpd       Fixed in")
    print("CVE-2026-119618  9.8 *  2.4.55 - 2.4.70      2.4.71")
    print("CVE-2026-106023  imp.   2.4.30 - 2.4.70      2.4.71")
    print("CVE-2026-109163  low    2.4.69 - 2.4.70      2.4.71")
    print()
    print("* Red Hat CVSS 3.1 9.8; NVD had not scored CVE-2026-119618")
    print("  as of 11 November 2026. Apache rates it critical.")
    print("Standalone mod_h2 from GitHub 2.0.8 - 2.0.42: vulnerable,")
    print("no fixed release yet. Distribution builds grade UNKNOWN:")
    print("distros backport fixes under the same version number.")


def _emit(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    label = result.get("label")
    if label:
        print(f"[{label}]")
    print(f"version: {result.get('version', '?')}")
    print(f"overall: {result['overall']}")
    for cve, detail in result.get("cves", {}).items():
        print(f"  {cve}: {detail['grade']} - {detail['note']}")
    for note in result.get("notes", []):
        print(f"  note: {note}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for the Apache httpd 2.4.71 "
        "batch (CVE-2026-119618, CVE-2026-106023, CVE-2026-109163)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", help="httpd version string, e.g. 2.4.63")
    group.add_argument("--version-file", help="file holding a version string")
    group.add_argument("--local", action="store_true",
                       help="detect the local httpd install")
    group.add_argument("--url", help="probe a remote httpd, read-only")
    group.add_argument("--mod-h2-version",
                       help="grade a standalone mod_h2 version, e.g. 2.0.42")
    group.add_argument("--inventory-json",
                       help="JSON list of {label, version} entries")
    group.add_argument("--list", action="store_true",
                       help="print the CVE table and exit")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable JSON output")
    parser.add_argument("--assume-upstream", action="store_true",
                        help="grade a distro build by its bare version "
                        "number; only use it when you know the build is "
                        "an upstream release, not a distro package")
    args = parser.parse_args(argv)

    if args.list:
        print_table()
        return 0

    try:
        if args.mod_h2_version:
            result = {"mod_h2": grade_mod_h2(args.mod_h2_version)}
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                detail = result["mod_h2"]
                print(f"mod_h2 {args.mod_h2_version}: {detail['grade']}")
                print(f"  {detail['note']}")
            return 2 if result["mod_h2"]["grade"] == "VULNERABLE" else 0

        if args.version:
            result = grade(args.version, assume_upstream=args.assume_upstream)
        elif args.version_file:
            result = grade(
                Path(args.version_file).read_text().strip(),
                assume_upstream=args.assume_upstream,
            )
        elif args.local:
            version_text, exposure, notes = detect_local()
            result = grade(
                version_text,
                exposure=exposure,
                assume_upstream=args.assume_upstream,
            )
            result["notes"] = notes
        elif args.url:
            result, notes = probe_url(args.url)
            result["notes"] = notes
        elif args.inventory_json:
            entries = json.loads(Path(args.inventory_json).read_text())
            results = grade_inventory(entries)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for entry_result in results:
                    _emit(entry_result, False)
                    print()
            return 2 if any(
                r["overall"] == "VULNERABLE" for r in results
            ) else 0
        else:  # pragma: no cover - argparse enforces one option
            parser.error("no scan mode given")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _emit(result, args.json)
    return 2 if result["overall"] == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
