#!/usr/bin/env python3
"""emudhra-checker — verify whether this system is affected by the eMudhra CA compromise."""

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

EMSIGN_ROOTS = [
    "emSign ECC Root CA - C3",
    "emSign ECC Root CA - G3",
    "emSign Root CA - C1",
    "emSign Root CA - G1",
]

FIXED_GO = {"1.26": 10, "1.27": 3}
FIXED_NODE = {"22": (23, 4), "24": (22, 1), "26": (12, 1)}
FIXED_CERTIFI = "2026.10.19"

TEST_DOMAINS = {
    "dv-g3b-emudhra.we-have-a-problem.com": "emSign direct",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com": "AAA cross-signed",
}


@dataclass
class Result:
    check: str
    status: str  # pass, fail, warn, info
    detail: str


def run(cmd: str, timeout: int = 15) -> str:
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        ).stdout.strip()
    except Exception as e:
        return f"error: {e}"


def check_ca_bundle() -> list[Result]:
    results = []
    ca_paths = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/usr/local/share/certs/ca-root-nss.crt",
    ]
    ca_file = next((p for p in ca_paths if os.path.isfile(p)), None)

    if ca_file:
        try:
            content = Path(ca_file).read_text()
            found = [r for r in EMSIGN_ROOTS if r in content]
            if found:
                results.append(Result("emSign in CA bundle", "fail",
                    f"{len(found)} entries: {', '.join(found)}"))
            else:
                results.append(Result("emSign in CA bundle", "pass", "no emSign entries"))
        except Exception as e:
            results.append(Result("CA bundle", "warn", f"could not read {ca_file}: {e}"))
    else:
        results.append(Result("CA bundle", "warn", "could not locate system CA bundle"))

    return results


def check_ca_package() -> list[Result]:
    results = []
    if shutil.which("dpkg"):
        ver = run("dpkg -l ca-certificates 2>/dev/null | awk '/^ii/{print $3}'")
        if ver:
            results.append(Result("ca-certificates (dpkg)", "info", ver))
    elif shutil.which("rpm"):
        ver = run("rpm -q ca-certificates 2>/dev/null")
        results.append(Result("ca-certificates (rpm)", "info", ver))
    elif shutil.which("apk"):
        ver = run("apk info ca-certificates 2>/dev/null | head -1")
        results.append(Result("ca-certificates (apk)", "info", ver or "not installed"))
    return results


def check_go() -> list[Result]:
    if not shutil.which("go"):
        return [Result("Go", "info", "not installed")]
    ver_str = run("go version")
    import re
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    if not m:
        return [Result("Go", "warn", f"could not parse: {ver_str}")]
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    key = f"{major}.{minor}"
    if key in FIXED_GO and patch >= FIXED_GO[key]:
        return [Result("Go", "pass", f"{m.group(0)} (has SPKI denylist)")]
    if minor >= 28:
        return [Result("Go", "pass", f"{m.group(0)}")]
    return [Result("Go", "fail", f"{m.group(0)} — needs >= 1.26.10 or >= 1.27.3")]


def check_node() -> list[Result]:
    if not shutil.which("node"):
        return [Result("Node.js", "info", "not installed")]
    ver_str = run("node --version").lstrip("v")
    parts = ver_str.split(".")
    if len(parts) < 3:
        return [Result("Node.js", "warn", f"could not parse: {ver_str}")]
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    for fixed_major, (fixed_minor, fixed_patch) in FIXED_NODE.items():
        if major == int(fixed_major):
            if minor > fixed_minor or (minor == fixed_minor and patch >= fixed_patch):
                return [Result("Node.js", "pass", f"{ver_str} (patched)")]
            return [Result("Node.js", "fail",
                f"{ver_str} — needs >= {fixed_major}.{fixed_minor}.{fixed_patch}")]
    if major > 26:
        return [Result("Node.js", "pass", f"{ver_str}")]
    return [Result("Node.js", "warn", f"{ver_str} — check against fixed version list")]


def check_certifi() -> list[Result]:
    try:
        import certifi
        ver = certifi.__version__
        ca_path = certifi.where()
        content = Path(ca_path).read_text()
        emsign_count = sum(1 for r in EMSIGN_ROOTS if r in content)
        if emsign_count > 0:
            return [Result("Python certifi", "fail",
                f"{ver} — {emsign_count} emSign entries in {ca_path}")]
        return [Result("Python certifi", "pass", f"{ver} (no emSign entries)")]
    except ImportError:
        return [Result("Python certifi", "info", "not installed")]
    except Exception as e:
        return [Result("Python certifi", "warn", str(e))]


def check_rust() -> list[Result]:
    results = []
    for lockfile in Path(".").rglob("Cargo.lock"):
        try:
            content = lockfile.read_text()
            import re
            for m in re.finditer(r'name = "webpki-roots"\nversion = "(\d+\.\d+\.\d+)"', content):
                ver = m.group(1)
                parts = [int(x) for x in ver.split(".")]
                if (parts[0] == 1 and parts[1] == 0 and parts[2] >= 10) or \
                   (parts[0] == 0 and parts[1] == 26 and parts[2] >= 11):
                    results.append(Result(f"webpki-roots ({lockfile})", "pass", ver))
                else:
                    results.append(Result(f"webpki-roots ({lockfile})", "fail",
                        f"{ver} — needs >= 1.0.10"))
        except Exception:
            pass
    if not results:
        results.append(Result("Rust webpki-roots", "info", "no Cargo.lock found"))
    return results


def check_tls() -> list[Result]:
    results = []
    if not shutil.which("curl"):
        return [Result("TLS tests", "warn", "curl not available")]
    for domain, label in TEST_DOMAINS.items():
        out = run(
            f'curl -sS --max-time 15 -o /dev/null -w "%{{http_code}}:%{{ssl_verify_result}}" '
            f'https://{domain}/ 2>&1'
        )
        if ":" in out:
            http, verify = out.split(":", 1)
            if http == "200" and verify == "0":
                results.append(Result(f"TLS {label} ({domain})", "fail",
                    f"ACCEPTED — HTTP {http}, verify={verify}"))
            else:
                results.append(Result(f"TLS {label} ({domain})", "pass", "REJECTED"))
        elif "SSL" in out or "certificate" in out or "error" in out:
            results.append(Result(f"TLS {label} ({domain})", "pass", "REJECTED"))
        else:
            results.append(Result(f"TLS {label} ({domain})", "warn", f"inconclusive: {out}"))
    return results


def check_nix() -> list[Result]:
    results = []
    nix_store = Path("/nix/store")
    if nix_store.is_dir():
        cacerts = [d.name for d in nix_store.iterdir() if "nss-cacert" in d.name]
        if cacerts:
            import re
            for c in cacerts:
                m = re.search(r"nss-cacert-(\d+\.\d+)", c)
                if m:
                    ver = m.group(1)
                    major, minor = ver.split(".")
                    if int(major) >= 3 and int(minor) >= 131:
                        results.append(Result("Nix cacert", "pass", f"{c} (>= 3.131)"))
                    else:
                        results.append(Result("Nix cacert", "fail",
                            f"{c} — needs >= 3.131.1"))
        else:
            results.append(Result("Nix cacert", "info", "no nss-cacert in /nix/store"))
    return results


def check_tmpfs() -> list[Result]:
    mounts = run("mount 2>/dev/null")
    if "on /etc/ssl/certs type tmpfs" in mounts:
        return [Result("tmpfs overlay", "warn",
            "/etc/ssl/certs is a tmpfs mount — OS package updates may be overridden")]
    return []


def check_env() -> list[Result]:
    results = []
    for var in ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"]:
        val = os.environ.get(var)
        if val:
            results.append(Result(var, "info", val))
    node_opts = os.environ.get("NODE_OPTIONS", "")
    if "--use-openssl-ca" in node_opts:
        results.append(Result("NODE_OPTIONS", "pass", "contains --use-openssl-ca"))
    elif node_opts:
        results.append(Result("NODE_OPTIONS", "info", f"{node_opts} (no --use-openssl-ca)"))
    return results


def main():
    all_results: list[Result] = []
    all_results.extend(check_ca_bundle())
    all_results.extend(check_ca_package())
    all_results.extend(check_go())
    all_results.extend(check_node())
    all_results.extend(check_certifi())
    all_results.extend(check_rust())
    all_results.extend(check_tls())
    all_results.extend(check_nix())
    all_results.extend(check_tmpfs())
    all_results.extend(check_env())

    passes = sum(1 for r in all_results if r.status == "pass")
    fails = sum(1 for r in all_results if r.status == "fail")
    warns = sum(1 for r in all_results if r.status == "warn")

    output = {
        "timestamp": run("date -u +%Y-%m-%dT%H:%M:%SZ"),
        "hostname": platform.node(),
        "os": platform.platform(),
        "pass": passes,
        "fail": fails,
        "warn": warns,
        "results": [asdict(r) for r in all_results],
    }

    if "--json" in sys.argv or "-j" in sys.argv:
        print(json.dumps(output, indent=2))
    else:
        print("emudhra-checker — eMudhra CA compromise verification\n")
        for r in all_results:
            tag = {"pass": "\033[32m[PASS]\033[0m", "fail": "\033[31m[FAIL]\033[0m",
                   "warn": "\033[33m[WARN]\033[0m", "info": "[INFO]"}.get(r.status, "[????]")
            print(f"  {tag} {r.check}: {r.detail}")
        print(f"\nSummary: {passes} passed, {fails} failed, {warns} warnings")
        if fails > 0:
            print(f"\n  \033[31m\033[1mVULNERABLE\033[0m — {fails} check(s) indicate exposure.")
            sys.exit(1)
        else:
            print("\n  \033[32m\033[1mNo issues detected.\033[0m")

    sys.exit(1 if fails > 0 else 0)


if __name__ == "__main__":
    main()
