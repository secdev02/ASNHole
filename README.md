# Certificate Validation Test Battery

A single-file Python script that generates cryptographically anomalous
certificate chains, signs `.exe` and `.dll` assemblies with each chain,
and exercises the Windows Authenticode validation engine against every
binary.  Any binary that produces an unexpected result — a validator
bypass, a false rejection, or a process crash — is preserved to a
UUID-stamped fault archive for further analysis.

---

## Purpose

Windows certificate validation involves dozens of interdependent checks
spread across CryptoAPI, WinVerifyTrust, and the Authenticode PKCS#7
pipeline.  A subtle bug in any one of those checks — a missing
`pathLenConstraint` enforcement, an ignored deprecated hash, an EKU
field that is accepted when it should be rejected — can silently allow
malicious code to appear signed by a trusted publisher.

This test battery exercises 21 distinct anomaly classes across all major
X.509 validation categories.  Each case has a declared `expected_valid`
flag; the battery flags a **fault** whenever the actual Authenticode
result does not match the expectation.

The battery is designed for:
- Developers writing or auditing certificate-validation code
- Security researchers testing custom trust policies or driver-signing
  enforcement layers
- Regression testing after changes to WinVerifyTrust or kernel CI policy

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Windows | 10 / Server 2019 | PowerShell 5.1+ must be present |
| Python | 3.9 | `pip install cryptography` |
| .NET Framework | 4.x | Provides `csc.exe` for assembly compilation |
| Elevated terminal | — | Required for root-store imports without UAC dialogs |

Install the Python dependency before running:

```
pip install cryptography
```

The `cryptography` package is the only third-party dependency.  All
other modules (`subprocess`, `uuid`, `json`, `pathlib`, …) are from the
standard library.

---

## Quick Start

```powershell
# Open an elevated PowerShell or Command Prompt, then:
python cert_test_battery.py
```

The script exits with code `0` when all results match expectations, and
`1` when one or more faults are detected.  Every step is written to the
console and to `C:\Test\CertValidation\logs\main.log` simultaneously.

### Optional: Microsoft kernel certificate cloning

If you place the real Microsoft kernel code-signing certificates at the
paths below before running, the script will also build and test a
synthetic clone of the full MS chain with fresh key pairs:

```
C:\Test\MSKernel32Root.cer
C:\Test\MSKernel32PCA.cer
C:\Test\MSKernel32Leaf.cer
```

The clone test is skipped silently when those files are absent; all
21 anomaly tests run regardless.

---

## Directory Layout

```
C:\Test\CertValidation\
  certs\
    valid-chain\          root.cer  ica.cer  leaf.pfx
    root-expired\         root.cer  ica.cer  leaf.pfx
    leaf-rogue-signature\ root.cer  ica.cer  leaf.pfx
    ica-path-len-exceeded\root.cer  ica.cer  sub_ica.cer  leaf.pfx
    …                     (one sub-folder per anomaly)
  assemblies\
    valid-chain\          valid-chain.exe  valid-chain.dll
    root-expired\         root-expired.exe  root-expired.dll
    …
  faults\
    3f2a1b0c-…\           (UUID — one folder per unexpected result)
      root-expired.exe
      root-expired.dll
      certs\              copy of all cert artefacts for this case
      fault_info.json
    …
  logs\
    main.log              full run transcript
    valid-chain-exe.ps1.log
    valid-chain-dll.ps1.log
    …                     (raw PowerShell I/O per case)
  source\
    valid-chain_exe.cs
    valid-chain_dll.cs
    …
  report.json             machine-readable summary of all results
```

---

## Anomaly Reference

### Baseline

| ID | Description | Expected |
|---|---|---|
| `VALID_CHAIN` | Standard 3-level chain — root → ICA → leaf, all constraints correct | **Valid** |

### Temporal

| ID | Description | Expected |
|---|---|---|
| `ROOT_EXPIRED` | Root CA `notAfter` is 10 years in the past | Invalid |
| `ROOT_NOT_YET_VALID` | Root CA `notBefore` is 1 day in the future | Invalid |
| `ICA_EXPIRED` | Intermediate CA `notAfter` is 10 years in the past | Invalid |
| `LEAF_EXPIRED` | Leaf `notAfter` is 10 years in the past | Invalid |
| `LEAF_NOT_YET_VALID` | Leaf `notBefore` is 1 day in the future | Invalid |

### Signature and Chain Integrity

| ID | Description | Expected |
|---|---|---|
| `LEAF_ROGUE_SIGNATURE` | Leaf cert is signed by a freshly generated unrelated key instead of the true ICA private key.  The issuer name and AKI match but signature verification against the ICA public key fails. | Invalid |
| `ICA_ROGUE_SIGNATURE` | Same attack one level up: the ICA cert is signed by a rogue key instead of the root's private key. | Invalid |
| `LEAF_SELF_SIGNED` | The leaf cert is self-issued (subject = issuer, signed by its own key).  No chain to any CA exists. | Invalid |
| `LEAF_BIT_FLIPPED` | After a valid leaf cert is created, bytes at DER offsets `[-220:-200]` from the end are XOR'd with `0xAA`.  This lands inside the 256-byte RSA signature value for a 2048-bit key without disturbing any ASN.1 structural bytes, so the cert still parses but signature verification fails. | Invalid |

### Key Usage and Extended Key Usage

| ID | Description | Expected |
|---|---|---|
| `LEAF_WRONG_EKU` | The leaf EKU extension contains `emailProtection` (OID 1.3.6.1.5.5.7.3.4) only.  The `codeSigning` OID (1.3.6.1.5.5.7.3.3) required by Authenticode is absent. | Invalid |
| `LEAF_NO_EKU` | The leaf certificate has no Extended Key Usage extension at all. | Invalid |
| `LEAF_KEY_USAGE_NO_SIGN` | The leaf Key Usage extension sets `keyEncipherment` but not `digitalSignature`.  The Authenticode pipeline requires the `digitalSignature` bit. | Invalid |

### Basic Constraints

| ID | Description | Expected |
|---|---|---|
| `LEAF_IS_CA` | The leaf certificate has `BasicConstraints CA:TRUE, pathLen:0`.  An end-entity certificate must not be a CA. | Invalid |
| `ICA_NO_CA_FLAG` | The `BasicConstraints` extension is omitted entirely from the intermediate CA cert.  Without an explicit `CA:TRUE` declaration the certificate cannot be used to sign other certificates. | Invalid |
| `ICA_PATH_LEN_EXCEEDED` | A four-level chain is built: root → ICA (`pathLenConstraint=0`) → sub-CA → leaf.  A `pathLen=0` value means the CA may sign only end-entity certificates, not further CAs.  The sub-CA violates this constraint. | Invalid |

### Signature Hash Algorithm

| ID | Description | Expected |
|---|---|---|
| `LEAF_MD5_SIGNATURE` | The leaf certificate's `signatureAlgorithm` is `md5WithRSAEncryption`.  Windows has banned MD5-signed certs from the Authenticode chain since early in the Vista era. | Invalid |
| `LEAF_SHA1_SIGNATURE` | The leaf certificate's `signatureAlgorithm` is `sha1WithRSAEncryption`.  SHA-1 code-signing certs are deprecated and rejected on Windows 10 1903 and later. | Invalid |

### Key Size

| ID | Description | Expected |
|---|---|---|
| `LEAF_WEAK_KEY_1024` | The leaf RSA key pair is 1024 bits.  Windows enforces a minimum of 2048 bits for Authenticode signing. | Invalid |

### Extensions

| ID | Description | Expected |
|---|---|---|
| `LEAF_UNKNOWN_CRITICAL` | The leaf cert contains a critical extension with a made-up OID (`2.99.999.1.2.3.4.5`) whose value is a DER NULL.  Per RFC 5280 §4.2, a validator that does not recognise a critical extension **must** reject the certificate. | Invalid |

### Trust Store

| ID | Description | Expected |
|---|---|---|
| `ROOT_NOT_TRUSTED` | The chain is cryptographically valid in every other respect.  The root CA cert is intentionally not installed in `Cert:\CurrentUser\Root` so the chain cannot be anchored to a trust point. | Invalid |

---

## Certificate Chain Architecture

Every anomaly is expressed through a `ChainSpec` dataclass that
parameterises a three-level hierarchy:

```
Root CA  (self-signed, pathLen=2)
  └── Intermediate CA  (pathLen=0)
        └── Leaf / End-Entity  (code-signing EKU)
```

The `ICA_PATH_LEN_EXCEEDED` case extends this to four levels:

```
Root CA  (self-signed, pathLen=2)
  └── ICA  (pathLen=0)            ← constraint is 0: must not sign CAs
        └── Sub-CA                ← VIOLATION: this cert is CA=TRUE
              └── Leaf
```

For `LEAF_SELF_SIGNED` the root and ICA are not generated at all:

```
Leaf  (self-signed, issuer = subject)
```

Each chain produces:
- `root.cer` — DER-encoded root certificate (no private key)
- `ica.cer` — DER-encoded intermediate CA certificate
- `sub_ica.cer` — DER-encoded sub-CA (path-len test only)
- `leaf.pfx` — PKCS#12 bundle containing the leaf private key, the leaf
  certificate, and the full chain of CA certificates

The PFX password for all artefacts is `TestBattery2024!` (configurable
in `§1 CONFIGURATION` at the top of the script).

---

## Test Lifecycle (per case)

Each test case executes the following steps inside a single `try/finally`
block so that cert-store cleanup is always guaranteed:

```
1.  Build cert chain          Python cryptography library
        ↓
2.  Compile assemblies        csc.exe → <label>.exe and <label>.dll
        ↓
3.  Install certs             PowerShell Import-Certificate / Import-PfxCertificate
      root.cer  → Cert:\CurrentUser\Root   (skipped for ROOT_NOT_TRUSTED)
      ica.cer   → Cert:\CurrentUser\CA
      leaf.pfx  → Cert:\CurrentUser\My
        ↓
4.  Sign binaries             PowerShell Set-AuthenticodeSignature
        ↓
5.  Validate signatures       PowerShell Get-AuthenticodeSignature
        ↓
6.  Load assemblies           PowerShell [System.Reflection.Assembly]::LoadFrom()
      invokes GetAssemblyInfo() on DLL, reads FullName on EXE
        ↓
7.  Execute EXE               subprocess.run() with 10-second timeout
        ↓
8.  Fault detection           compare actual IsValid to expected_valid
        ↓                     log PS crashes (rc < 0)
9.  Preserve fault            copy binaries + certs to faults\{UUID}\
        ↓                     write fault_info.json
10. Cleanup                   Remove-Item from all three stores
```

---

## Fault Detection

A test is flagged as a **fault** when any of the following conditions hold:

- `Get-AuthenticodeSignature` returns `IsValid = True` for a case where
  `expected_valid = False` — a genuine validation bypass.
- `Get-AuthenticodeSignature` returns `IsValid = False` for the
  `VALID_CHAIN` baseline — a false positive that could break legitimate
  software.
- The PowerShell host process exits with a negative return code during
  signing or validation — indicating a crash or unhandled exception.

Faults are preserved under `faults\{uuid}\` and the script exits with
code `1`.  Non-fault errors (compilation failures, PFX import failures)
are logged but do not set the fault flag or the exit code.

### `fault_info.json` schema

```jsonc
{
  "test_id":        "3f2a1b0c-…",       // UUID
  "anomaly_id":     "ROOT_EXPIRED",
  "description":    "Root CA notAfter is in the past",
  "expected_valid": false,
  "fault_reason":   "Authenticode IsValid=True but expected False …",
  "spec": {                             // full ChainSpec as used
    "root_key_bits": 2048,
    "root_valid_from": "2015-01-01T00:00:00+00:00",
    "root_valid_to":   "2015-01-01T00:00:00+00:00",
    …
  },
  "sign_exe":     { "Status": "…", "StatusMessage": "…" },
  "sign_dll":     { "Status": "…", "StatusMessage": "…" },
  "validate_exe": { "Status": "…", "IsValid": true,  … },
  "validate_dll": { "Status": "…", "IsValid": true,  … },
  "load_exe":     { "loaded": true,  "output": "…" },
  "load_dll":     { "loaded": true,  "output": "…" },
  "run_exe":      { "rc": 0, "stdout": "…" },
  "timestamp":    "2024-06-01T12:00:00+00:00"
}
```

---

## `report.json` Schema

```jsonc
{
  "generated_utc": "2024-06-01T12:00:00+00:00",
  "total":   22,    // includes optional CLONED_MS
  "clean":   20,
  "faults":   1,
  "errors":   1,
  "results": [
    {
      "test_id":        "…",
      "anomaly_id":     "VALID_CHAIN",
      "description":    "…",
      "expected_valid": true,
      "category":       "baseline",
      "is_fault":       false,
      "fault_reason":   "",
      "fault_dir":      "",
      "error":          "",
      …
    },
    …
  ]
}
```

---

## Compiler Discovery

The script searches for a C# compiler in this order:

1. `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`
2. `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
3. Roslyn `csc.dll` under `C:\Program Files\dotnet\sdk\*\Roslyn\bincore\`
   (latest SDK version preferred)

If no compiler is found the script logs an error and exits with code `1`
before any tests run.  Install the .NET Framework 4.x Developer Pack or
the .NET SDK and retry.

---

## Windows Certificate Store Layout

| Store | Path | What is imported |
|---|---|---|
| Personal | `Cert:\CurrentUser\My` | Leaf PFX (cert + private key) |
| Intermediate CA | `Cert:\CurrentUser\CA` | ICA and sub-CA `.cer` files |
| Trusted Root | `Cert:\CurrentUser\Root` | Root `.cer` (skipped for `ROOT_NOT_TRUSTED`) |

All three stores are cleaned up in the `finally` block of each test case,
identified by the SHA-1 thumbprints captured at import time.  Cleanup is
best-effort; failures are logged but do not abort subsequent tests.

> **Note on UAC prompts:** On some Windows configurations, adding a
> self-signed certificate to `Cert:\CurrentUser\Root` triggers a security
> dialog even when using the PowerShell `Import-Certificate` cmdlet.
> Running the script from an **elevated** terminal suppresses this dialog
> for the duration of the run.

---

## Generated C# Source

Both the `.exe` and `.dll` assembly types are generated from in-memory
C# source strings and compiled fresh for each test case.

**Executable** (`Program.Main`):
```csharp
Console.WriteLine("Name  : " + asm.GetName().Name);
Console.WriteLine("MVID  : " + asm.ManifestModule.ModuleVersionId.ToString());
Console.WriteLine("UTC   : " + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
```

**Library** (`TestLibrary`):
```csharp
public static string GetAssemblyInfo()
{
    return string.Format(
        "Library={0}  MVID={1}  UTC={2}",
        asm.GetName().Name,
        asm.ManifestModule.ModuleVersionId.ToString(),
        DateTime.UtcNow.ToString("O")
    );
}
```

String concatenation and `string.Format()` are used throughout; C#
string interpolation is not used.

---

## Configuration Reference

All runtime constants are declared at the top of the script in `§1 CONFIGURATION`
and can be edited without modifying any logic:

| Constant | Default | Purpose |
|---|---|---|
| `BASE_DIR` | `C:\Test\CertValidation` | Root of all output |
| `MS_CERT_DIR` | `C:\Test` | Where to look for original MS certs |
| `PFX_PASSWORD` | `TestBattery2024!` | PKCS#12 encryption password |
| `STORE_MY` | `Cert:\CurrentUser\My` | Personal store path |
| `STORE_ROOT` | `Cert:\CurrentUser\Root` | Trusted root store path |
| `STORE_CA` | `Cert:\CurrentUser\CA` | Intermediate CA store path |

Time anchors (used for temporal anomalies) are derived from the moment
`main()` starts and are not separately configurable; adjust the
`datetime.timedelta` values in `§1` if different offset windows are needed.

---

## Source Code Map

| Section | Lines | Responsibility |
|---|---|---|
| §1 Configuration | ~30 | Paths, passwords, time anchors |
| §2 Anomaly Registry | ~115 | `ANOMALIES` dict — 21 entries with `desc`, `expected_valid`, `category` |
| §3 Dataclasses | ~60 | `ChainSpec` and `TestRecord` |
| §4 Logging | ~20 | Dual handler setup (file + stdout) |
| §5 Crypto helpers | ~175 | Key generation, cert builders, PFX/CER export, bit-flip |
| §6 Chain builder | ~150 | `_spec_for()` factory; `build_chain()` assembler |
| §7 Compilation | ~75 | `_find_csc()`, `_compile()`, `compile_assemblies()` |
| §8 PowerShell | ~130 | `_ps()` wrapper; import, sign, validate, load, run |
| §9 Fault tracker | ~60 | `_is_fault()`, `_preserve_fault()` |
| §10 MS cloning | ~90 | `_clone_ms_certs()` — optional, triggered by file presence |
| §11 Test runner | ~135 | `_run_one()` — drives the 10-step lifecycle per case |
| §12 Report | ~25 | `_generate_report()` → `report.json` |
| §13 main | ~65 | Entry point, compiler discovery, loop over all anomalies |

---

## Extending the Battery

### Adding a new anomaly

1. Add an entry to the `ANOMALIES` dict in `§2`:

```python
"MY_NEW_ANOMALY": {
    "desc": "One-line description of what is wrong",
    "expected_valid": False,
    "category": "my_category",
},
```

2. Add an `elif` branch in `_spec_for()` in `§6`:

```python
elif anomaly_id == "MY_NEW_ANOMALY":
    s.leaf_eku = ["email"]   # or whichever ChainSpec fields apply
```

3. Re-run — the new case is picked up automatically.

### Running a single anomaly

Import the module and call `_run_one()` directly:

```python
from cert_test_battery import _run_one, _find_csc, _setup_logging, _init_dirs

_setup_logging()
_init_dirs()
csc = _find_csc()
results = []
_run_one(
    anomaly_id="LEAF_BIT_FLIPPED",
    description="manual single run",
    expected_valid=False,
    category="signature",
    csc=csc,
    results=results,
)
print(results[0])
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All test results matched their `expected_valid` declarations |
| `1` | One or more faults detected, or no compiler was found |
