# eMudhra CA Intermediate Key Compromise — Deep Technical Analysis

**Date:** 2026-10-22  
**Author:** [Qi Deng](https://github.com/ikow)

## Timeline

| Date | Event |
|------|-------|
| 2026-10-17 | Researcher Wayne reports 8 weak intermediate keys to root programs and eMudhra |
| 2026-10-17 | Mozilla independently verifies the report |
| 2026-10-17 | Mozilla ships NSS 3.131.1 — removes emSign ECC Root CA - G3 from trust store |
| 2026-10-18 | Go 1.26.10, 1.27.3 released with SPKI hash denylist (CVE-2026-111943) |
| 2026-10-19 | Python certifi 2026.10.19 released |
| 2026-10-20 | Rust webpki-roots 1.0.10, rustls-webpki 0.103.16 released |
| 2026-10-20 | curl CA bundle updated |
| 2026-10-20 | Ubuntu, Debian, Alpine, Fedora, Arch release updated ca-certificates |
| 2026-10-21 | Node.js 22.23.4, 24.22.1, 26.12.1 released |
| 2026-10-21 | Electron 42.11.16, 43.8.1, 44.9.1 released |

## Technical Root Cause

### The P-384 Key Generation Failure

The 8 compromised certificates use P-384 (secp384r1) elliptic curve keys. A valid P-384 private key is a 384-bit (48-byte) integer uniformly sampled from [1, n-1] where n is the curve order (~3.6 × 10^115).

The compromised private keys are **integers less than 256**. In their 48-byte big-endian representation, the first 47 bytes are all zeros and only the last byte is non-zero. This means:

- The key space is 255 values instead of ~2^384
- Any attacker can recover the private key by trying all 255 possibilities
- Standard baby-step giant-step or Pollard's rho algorithms solve it in microseconds
- Multiple researchers independently recovered all 8 keys within hours of disclosure

### eMudhra's Explanation

eMudhra attributed the failure to their Key Generation Ceremony (KGC) on a Utimaco HSM (FIPS 140-2 Level 3):

1. The ceremony script was intended to generate a P-384 key pair on the HSM
2. A second, weaker key pair was inadvertently generated on the HSM board
3. Due to similar key labels, the CSR was signed with the weak key pair
4. The error was not caught by ceremony witnesses or auditors
5. A series ("A") and A-1 series certificates were generated on a different Entrust HSM and are unaffected
6. RSA keys used a different code path and are unaffected

Mozilla noted that CRLs with invalid signatures have timestamps predating eMudhra's claimed creation date for the A-1 series, raising questions about the explanation.

## Impact Assessment

### Who Is Affected

Any system that has **emSign ECC Root CA - G3** in its trust store is vulnerable. An attacker with the recovered private keys can:

1. **Issue certificates for any domain** — forge `*.google.com`, `*.bank.com`, etc.
2. **MITM any HTTPS connection** — silently intercept and modify encrypted traffic
3. **Sign malicious code** — the 2 code-signing intermediates allow signing executables that appear legitimate
4. **Bypass certificate pinning** — in systems that pin to the CA rather than the leaf

### Trust Store Complexity

Modern systems have **multiple independent trust stores**, each requiring separate updates:

| Trust Store | Update Mechanism |
|-------------|-----------------|
| System CA bundle (`/etc/ssl/certs/`) | OS package manager (apt, dnf, apk) |
| Go `crypto/x509` | Go version upgrade (SPKI denylist) |
| Node.js | Node version upgrade (embedded Mozilla roots) |
| Python `certifi` | pip upgrade |
| Rust `webpki-roots` | Cargo dependency update |
| Java cacerts | JDK update |
| Browser NSS/BoringSSL | Browser auto-update |
| Nix `cacert` | Nix package rebuild |
| Container runtime | Image rebuild + rollout |

### The Container Trap

In containerized environments, updating the OS `ca-certificates` package may be **necessary but insufficient**:

```
┌─────────────────────────────────┐
│  Container Runtime              │
│  ┌───────────────────────────┐  │
│  │ tmpfs on /etc/ssl/certs   │  │  ← What OpenSSL/curl actually read
│  │ (written by PID1 from     │  │
│  │  Nix cacert at startup)   │  │
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │ /etc/ssl/certs (rootfs)   │  │  ← apt ca-certificates update goes here
│  │ (hidden by tmpfs mount)   │  │     but it's invisible to applications
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │ Node.js embedded roots    │  │  ← Separate, needs Node version upgrade
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │ Python certifi            │  │  ← Separate, needs pip upgrade
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

We observed this in a production Cloud Run deployment:
- `ca-certificates 20260816ubuntu0.24.04.1` was installed (patched)
- The package correctly removed `emSign_ECC_Root_CA_-_G3.crt`
- But PID1 mounted tmpfs over `/etc/ssl/certs` with a bundle from `nss-cacert-3.117` (unpatched)
- All TLS operations used the tmpfs bundle — emSign chains still accepted

### CI Cache Pitfall

Nix build systems may serve cached artifacts from before the fix:

```
Tagged outPath: "/nix/store/...-image-pid1.json"
No change for pid1, skipping.
```

Even after merging the fix code, if the Nix derivation hash hasn't changed (e.g., the Go source filter doesn't capture new files, or the derivation inputs haven't changed), the CI reuses the old cached binary. The fix is merged in git but never compiled into the deployed binary.

## Verification

### Testing with Live Endpoints

The [we-have-a-problem.com](https://we-have-a-problem.com/) domain serves certificates through the compromised eMudhra intermediates:

```bash
# Should FAIL (connection rejected) on a patched system
curl -v https://dv-g3b-emudhra.we-have-a-problem.com/

# Should also FAIL
curl -v https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

If curl returns HTTP 200 with `ssl_verify_result=0`, your system trusts the compromised chain.

### Checking the Bundle Source

```bash
# Is /etc/ssl/certs a tmpfs overlay?
mount | grep ssl

# What Nix cacert version is in use?
ls /nix/store/ | grep nss-cacert

# Does the binary contain the filter code?
strings /usr/local/bin/pid1 | grep -i emudhra
```

## References

- [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [eMudhra Incident Report](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c14)
- [CVE-2026-111943](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943) (Go)
- [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) (webpki-roots)
- [NSS 3.131.1](https://github.com/mozilla/nss/blob/master/doc/src/releases/nss_3_131_1.md)
- [we-have-a-problem.com](https://we-have-a-problem.com/) (test endpoints)
