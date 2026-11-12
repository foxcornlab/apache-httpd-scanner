# `apache-httpd-scanner`

Local triage for the `Apache HTTP Server 2.4.71` batch, headlined by `CVE-2026-119618`, a critical heap corruption and `RCE` in `mod_http2`. Give it an `httpd` version you own, the host it runs on, or a `URL`, and it tells you whether that install is still open. It never sends a payload, never runs an exploit, never sends an `HTTP/2` preface or a crafted request.

## `The flaw`

On `11 November 2026` the `Apache HTTP Server` project released `httpd 2.4.71`, a security release fixing three `CVE`s. The headline is `CVE-2026-119618` (`CWE-362`, concurrent execution on a shared resource): a race in `assign_headers()` inside `mod_http2` corrupts the heap when an `HTTP/2` request carries a `Content-Type` header and ends immediately with `END_STREAM` and no `Content-Length`. `Apache` rates it `critical` and says it can lead to `RCE`; `Red Hat` scores it `CVSS 3.1 9.8` (`AV:N/AC:L/PR:N/UI:N`, no privileges, no user interaction). It affects `httpd 2.4.55` through `2.4.70` and the standalone `mod_h2` module from `GitHub` `2.0.8` through `2.0.42`. It was found independently by `Anthropic's OSS Scanner` (reported `26 October 2026`) and by `Anthony Weems` and `Simon Scannell` of `Google Cloud Vulnerability Research` (reported `3 November 2026`). No exploitation in the wild or public exploit code has been reported as of `11 November 2026`.

The other two in the batch are `CVE-2026-106023` (`important`): a `NULL` pointer dereference in `mod_md` during request processing, `2.4.30` through `2.4.70`, a child-process crash; and `CVE-2026-109163` (`low`): a one-byte stack buffer overwrite in `mod_vhost_alias`, a follow-on to `CVE-2026-63292`, only `2.4.69` and `2.4.70`.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `2.4.63` on `Debian`, `Ubuntu`, `RHEL` | `UNKNOWN` | **The distro-backport trap.** Distros backport security fixes into their own `httpd` packages while keeping the upstream version number, so `2.4.52` on `Ubuntu` may already carry the fix, or may not, and the version string cannot tell you. This tool refuses to clear it. Check your vendor tracker (`Debian DSA`, `Ubuntu USN`, `RHSA`). Pass `--assume-upstream` only when you know the build is an upstream release, not a distro package. |
| Standalone `mod_h2 2.0.42` | `VULNERABLE` | **The latest-is-still-broken trap.** `2.0.42` is the latest `mod_h2` release and it is still vulnerable. There is no fixed `mod_h2` release yet, so do not go back to the standalone module. Use the `httpd 2.4.71` bundled `mod_http2` instead. |
| `2.4.63` with `mod_http2` off | `NOT-EXPOSED` | `CVE-2026-119618` only bites when `mod_http2` is loaded and `HTTP/2` is on. Same logic per flaw: `mod_md` off clears `CVE-2026-106023`, `mod_vhost_alias` off clears `CVE-2026-109163`. A version in range with the module off is not vulnerable, it is not exposed. |
| `Server: Apache` with no version | `UNKNOWN` | **The masked-banner trap.** `ServerTokens Prod` strips the version, so there is nothing to grade. It is not clean, it is ungraded. |
| `2.4.54` | `NOT-AFFECTED` for `CVE-2026-119618`, `VULNERABLE` for `CVE-2026-106023` | Each `CVE` has its own range. Being below the headline flaw does not clear the batch. This tool grades all three separately and reports the worst. |
| `2.4.69` or `2.4.70` | `VULNERABLE` on all three | The only two releases open to the whole batch, including the `mod_vhost_alias` flaw that exists nowhere else. |
| `httpd 2.2.x` | `UNKNOWN` | The advisory covers the `2.4` line only. `2.2` is end of life. It has not been cleared, only left ungraded. |

## `What it checks`

- `One install` (`--version 2.4.63`): graded against the fixed release, per `CVE`
- `A Server header` (`--version "Server version: Apache/2.4.63 (Debian)"`): parsed, distro builds flagged
- `The host it runs on` (`--local`): reads `httpd -v`, lists modules with `-M`, reads `Protocols` lines from the config, so exposure is real, not assumed
- `A remote server` (`--url https://example.com`): one plain `HEAD` request reads the `Server` header, and over `TLS` the handshake offers `ALPN h2` to learn whether the server negotiates `HTTP/2`. No `HTTP/2` preface, no crafted request
- `A standalone mod_h2` (`--mod-h2-version 2.0.42`): graded against the `2.0.8` to `2.0.42` range with no fixed release
- `A version file` (`--version-file version.txt`): first line is the version, which may be a full `httpd -v` line
- `A fleet, offline` (`--inventory-json sites.json`): a `JSON` list of `{label, version}` entries, with optional `http2`, `mod_md`, `mod_vhost_alias` booleans per host
- `The full table` (`--list`): affected ranges, fixed release, the `mod_h2` trap
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 apache_httpd_scanner.py --version 2.4.63
python3 apache_httpd_scanner.py --local
python3 apache_httpd_scanner.py --url https://example.com
python3 apache_httpd_scanner.py --mod-h2-version 2.0.42
python3 apache_httpd_scanner.py --version-file version.txt
python3 apache_httpd_scanner.py --inventory-json sites.json
```

```json
[
  {"label": "web-01", "version": "2.4.63", "http2": true},
  {"label": "web-02", "version": "2.4.71"},
  {"label": "web-03", "version": "Server version: Apache/2.4.62 (Debian)"}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

Find your `httpd` version with `httpd -v` or `apache2 -v` on the host, from the `Server` header, or from your package manager (`dpkg -l apache2`, `rpm -q httpd`). If the package version carries a distro suffix, expect `UNKNOWN` and check your vendor tracker.

## `The table`

| `CVE` | `Score` | `Affected httpd` | `Fixed in` |
| --- | --- | --- | --- |
| `CVE-2026-119618` | `9.8` * | `2.4.55` to `2.4.70` | `2.4.71` |
| `CVE-2026-106023` | `important` | `2.4.30` to `2.4.70` | `2.4.71` |
| `CVE-2026-109163` | `low` | `2.4.69` to `2.4.70` | `2.4.71` |

\* `Red Hat CVSS 3.1 9.8`; `NVD` had not scored `CVE-2026-119618` as of `11 November 2026`. `Apache` rates it `critical`. Standalone `mod_h2 2.0.8` to `2.0.42`: vulnerable, no fixed release yet.

## `What this tool does not do`

It does not test the race condition. Testing it would mean firing concurrent `HTTP/2` requests at a live server to corrupt its heap, which is an attack, not a version check. It does not scan the network for `httpd` installs, and it does not fetch or use any proof of concept. Over plain `HTTP` it cannot confirm `HTTP/2` support without sending an `HTTP/2` preface, which it never does, so `h2` status stays unknown there unless you confirm `Protocols` in the config.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`55` tests, all passing: version parsing in every accepted form (`httpd -v` lines, `Debian`/`Ubuntu`/`Red Hat` builds, `Win64` upstream builds, `v`-prefix, masked banners, garbage), the grading boundaries for all three `CVE`s on both sides of each range, the module-exposure rules (`NOT-EXPOSED` when a module is off, assumed-loaded when unknown), the distro-backport trap and the `--assume-upstream` override, the standalone `mod_h2` trap (`2.0.42` still vulnerable, `2.0.43` unknown), local detection against a fake `httpd` binary (including `Protocols` parsing), remote probing against a mock `HTTP` server (vulnerable, patched, masked, and missing-`Server`-header cases), `CLI` exit codes, `JSON` output, and inventory grading.

## `Sources`

- `Apache HTTP Server 2.4 vulnerabilities` page (`httpd.apache.org/security/vulnerabilities_24.html`), read `12 November 2026`: `2.4.71` released `11 November 2026`, `3 CVE`s; `CVE-2026-119618` affects `2.4.55` through `2.4.70` and `mod_h2 2.0.8` through `2.0.42`, fix commit `824beab9b9424d6cfb29595248fdbf6c3dddeab1`; `CVE-2026-106023` affects `2.4.30` through `2.4.70`; `CVE-2026-109163` affects `2.4.69` and `2.4.70`
- `Red Hat` assessment, via `PBXScience` `11 November 2026`: `CVE-2026-119618 CVSS 3.1 9.8`, `AV:N/AC:L/PR:N/UI:N`
- `SecurityOnline` and `ScanRadar`, `11 November 2026`: no exploitation in the wild and no public exploit code reported; `NVD` had not scored the flaws yet
- `CodeIT`, `11 November 2026`: `httpd 2.4.71` packages shipped the same day for `EL` and `Ubuntu`; the standalone `mod_h2` has no fixed release yet (`2.0.42` is the latest)
- `nuclei-templates`, checked `12 November 2026`: no template for `CVE-2026-119618`, `CVE-2026-106023`, or `CVE-2026-109163` (all `404`)

Three disagreements to note. First, `NVD` had not scored `CVE-2026-119618` as of `11 November`; this tool follows `Red Hat`'s `9.8` for the headline score, which agrees with `Apache`'s `critical` rating. Second, one vendor table lists the standalone `mod_h2` fix as `2.0.24` and newer, while its own remediation text says to upgrade beyond `2.0.42`, and `Apache` lists no fixed `mod_h2` release; this tool follows `Apache`, `2.0.42` is still vulnerable. Third, `CVE-2026-119618` has no `KEV` entry and no confirmed exploitation as of writing, so this pick rests on the `9.8` score and the breadth of `httpd` deployment, not on active exploitation.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.

## `Thanks to`

- `Anthropic's OSS Scanner`, `Anthony Weems` and `Simon Scannell` of `Google Cloud Vulnerability Research` for finding `CVE-2026-119618`
- `hexb1n`, `Yang Song`, `JiaSheng He` of `360 Vulnerability Research Institute`, `Lucian Nitescu` and `Bartlomiej Dmitruk` for `CVE-2026-106023`
- `Gustavo Aiello`, `Charles Vosburgh`, `Wojciech Tatarski`, `Oz Kaiser` and `Daisuke Hatakeyama` for `CVE-2026-109163`
- The `Apache HTTP Server` project for the fix and the advisory

## `Disclaimer`

Educational and defensive use only. This tool grades version strings against a published fix table. It is not a scanner for finding live targets, and it does not exploit anything. Use it on systems you own or are authorised to test.
