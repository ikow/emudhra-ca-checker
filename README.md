<h1 align="center">emudhra-ca-checker</h1>
<p align="center">
  <strong>eMudhra CA Intermediate Key Compromise — Detection & Verification Toolkit</strong>
</p>
<p align="center">
  <a href="https://github.com/ikow/emudhra-ca-checker/stargazers"><img src="https://img.shields.io/github/stars/ikow/emudhra-ca-checker?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-9.1%20Critical-red?style=flat-square" alt="Critical">
  <img src="https://img.shields.io/badge/Intermediates-8%20compromised-red?style=flat-square" alt="8 Intermediates">
  <img src="https://img.shields.io/badge/Key%20Size-≤%201%20byte-red?style=flat-square" alt="Key Size">
  <img src="https://img.shields.io/badge/Products-28%2B%20affected-orange?style=flat-square" alt="28+ Products">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> · <a href="#what-it-checks">Checks</a> · <a href="#fixed-versions">Fixed Versions</a> · <a href="docs/ANALYSIS.md">Deep Analysis</a> · <a href="https://qideng.substack.com">Writeup</a>
</p>

---

Eight P-384 intermediate CA certificates issued by eMudhra had **private keys that were trivially small integers (< 256)** — effectively 1-byte keys on a curve designed for 192-bit security. Anyone can recover these keys in milliseconds. Six were TLS intermediates; two were code-signing intermediates. An attacker with these keys can **forge certificates trusted by any unpatched system**, enabling silent MITM of any HTTPS connection.

This toolkit checks whether your systems, containers, and CI pipelines are still vulnerable.

**Author:** [Qi Deng](https://github.com/ikow) &nbsp;|&nbsp; **Date:** 2026-10-22

## Background

On October 17, 2026, security researcher Wayne [reported](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) to Mozilla and other root programs that 8 eMudhra intermediate CA certificates had catastrophically weak private keys. The P-384 private key values were less than 256 — all zeros except the last byte. Mozilla verified and shipped a fix within 3 hours.

The root cause: a key generation ceremony script error on a Utimaco HSM (FIPS 140-2 Level 3) caused the CSR to use a weak test key instead of the properly generated key.

## Compromised Certificates

**6 TLS intermediates** (issuer: emSign Root TLS CA - G3):

| Common Name | Serial | Type |
|-------------|--------|------|
| EM DV TLS CA - G3A | `21:8F:CD` | Domain Validation |
| EM DV TLS CA - G3B | `21:8F:CE` | Domain Validation |
| EM OV TLS CA - G3A | `21:8F:CF` | Organization Validation |
| EM OV TLS CA - G3B | `21:8F:D0` | Organization Validation |
| EM EV TLS CA - G3A | `21:8F:D1` | Extended Validation |
| EM EV TLS CA - G3B | `21:8F:D2` | Extended Validation |

**2 code-signing intermediates** (issuer: emSign Root CS CA - G3):

| Common Name | Serial | Type |
|-------------|--------|------|
| EM CS CA - G3A | `21:8F:D3` | Code Signing |
| EM CS CA - G3B | `21:8F:D4` | Code Signing |

Additionally, 8 Sectigo (AAA Certificate Services) cross-signed variants of the same keys exist. See [`data/compromised-certs.json`](data/compromised-certs.json) for full SHA-256 fingerprints and SPKI hashes.

## Quick Start

One-liner:

```bash
curl -sSL https://raw.githubusercontent.com/ikow/emudhra-ca-checker/main/checker/check.sh | bash
```

Or clone:

```bash
git clone https://github.com/ikow/emudhra-ca-checker.git
cd emudhra-ca-checker
./checker/check.sh
```

JSON output:

```bash
./checker/check.sh --json
```

Python (also checks certifi CA store):

```bash
python3 checker/check.py
```

Test inside a Docker image:

```bash
./checker/check-docker.sh ubuntu:24.04
./checker/check-docker.sh node:24-alpine
./checker/check-docker.sh golang:1.26
```

## What It Checks

| Check | Description |
|-------|-------------|
| **System CA bundle** | emSign root CAs in `/etc/ssl/certs/ca-certificates.crt` and macOS keychain |
| **ca-certificates package** | Installed version vs. known-fixed versions (dpkg, rpm, apk) |
| **Go** | >= 1.26.10 or >= 1.27.3 for [CVE-2026-111943](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943) SPKI denylist |
| **Node.js** | >= 22.23.4, >= 24.22.1, or >= 26.12.1 |
| **Python certifi** | >= 2026.10.19 |
| **Rust webpki-roots** | Scans `Cargo.lock` for webpki-roots < 1.0.10 |
| **OpenSSL / curl** | Version reporting |
| **TLS live test** | Connects to [we-have-a-problem.com](https://we-have-a-problem.com/) test domains serving certs through the compromised intermediates |
| **Nix cacert** | Outdated `nss-cacert` in `/nix/store` (needs >= 3.131.1) |
| **tmpfs overlay** | Detects if `/etc/ssl/certs` is a tmpfs mount — common in container runtimes where the OS CA bundle is overridden at startup |
| **Environment** | `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_OPTIONS` (checks for `--use-openssl-ca`) |

## Fixed Versions

| Product | Fixed Version |
|---------|---------------|
| Go | 1.26.10, 1.27.3 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| Electron | 42.11.16, 43.8.1, 44.9.1 |
| Python certifi | 2026.10.19 |
| pip | 26.2.2 |
| uv | 0.13.4 |
| Mozilla NSS | 3.131.1 |
| Rust webpki-roots | 1.0.10 |
| Rust rustls-webpki | 0.103.16 |
| Rustup | 1.29.2 |
| curl CA bundle | 2026-10-20 |
| Ubuntu ca-certificates | 20260816ubuntu0.24.04.1 |
| Debian ca-certificates | 20250419~deb12u2 |
| Alpine ca-certificates | 20261020-r0 |
| Fedora ca-certificates | 2026.2.92_v9.0.319 |
| Arch ca-certificates-mozilla | 3.131.1-1 |
| Homebrew ca-certificates | 2026-09-25_1 |
| Composer ca-bundle | 1.4.16, 1.6.0 |
| Elixir castore | 1.0.22 |

See [`data/fixed-versions.json`](data/fixed-versions.json) for the complete machine-readable list (28 products).

## Container & Nix Pitfalls

Updating the OS `ca-certificates` package may **not be sufficient** in containerized environments:

1. **tmpfs overlay** — Container runtimes (PID1, Replvisor) may mount a tmpfs over `/etc/ssl/certs` and populate it from a Nix `cacert` derivation at startup. The OS package update is on the underlying filesystem, hidden by the mount.

2. **Nix cacert** — If the Nix `cacert` package is built from NSS < 3.131.1, the tmpfs bundle still contains emSign roots. Check with:
   ```bash
   ls /nix/store/ | grep nss-cacert
   ```

3. **Embedded trust stores** — Node.js, Rust (`webpki-roots`), and Python (`certifi`) ship their own CA root lists. System CA updates don't fix these — each needs its own version upgrade.

4. **CI cache** — Nix build caches may serve a pre-fix binary even after the fix is merged. Verify the deployed binary actually contains the filter code, not just that the source was merged.

This checker detects all of these scenarios.

## Advisories

- [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) — Original report and root program response
- [CVE-2026-111943](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943) — Go SPKI denylist
- [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) — webpki-roots
- [RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html) — webpki-root-certs
- [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383.html) — rustls-webpki
- [NSS 3.131.1 Release Notes](https://github.com/mozilla/nss/blob/master/doc/src/releases/nss_3_131_1.md)
- [we-have-a-problem.com](https://we-have-a-problem.com/) — Live test endpoints with compromised intermediate chains

## Repo Structure

```
├── checker/
│   ├── check.sh           # Bash checker (main tool)
│   ├── check.py           # Python checker (+ certifi)
│   └── check-docker.sh    # Test inside Docker images
├── data/
│   ├── compromised-certs.json   # All 16 compromised certs
│   └── fixed-versions.json      # 28 products, fixed versions
├── docs/
│   └── ANALYSIS.md        # Deep technical analysis
└── .github/
    └── workflows/
        └── check.yml      # CI across ubuntu, macOS, containers
```

## License

MIT
