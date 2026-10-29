# Security policy

## Reporting a vulnerability

Please report security problems **privately** – not in a public issue:

- GitHub: *Security › Report a vulnerability* in this repository (private vulnerability reporting), or
- e-mail: **info@sediccodestudio.de** – subject “Security: SCS Scanner”.

Please include the affected version, the system, steps to reproduce and, if possible, a proof of concept.
We confirm receipt within 7 days and aim to publish a fix within 30 days. We credit reporters in the release notes
unless you prefer to stay anonymous. Good-faith research that respects the privacy of others is welcome; please do not
access data that is not yours.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no – please update |

## Verifying a download

Every release lists the SHA-256 checksums of its files (`SHA256SUMS`), and the release files carry a signed build
provenance attestation created by GitHub Actions. To check a file:

```sh
shasum -a 256 -c SHA256SUMS            # Linux / macOS
gh attestation verify scs.pyz --repo SedicCodeStudio/scs-scanner
```

```powershell
Get-FileHash .\scs.ps1 -Algorithm SHA256   # compare with SHA256SUMS
```

The release build is reproducible: `python3 tools/build_release.py` on the tagged source produces byte-identical files.
Each release also contains a software bill of materials (`sbom.cdx.json`, CycloneDX 1.5) that lists every part of the
release and where third-party components come from.

## Design principles

- Read-only by default. Nothing is deleted without an explicit confirmation; the quarantine moves files, it never deletes them.
- No telemetry. The only network requests are the downloads of the indicator lists (and optionally the YARA rules)
  from their public sources over HTTPS. Reports stay on your computer.
- No third-party Python packages are required; optional extras are clearly marked.
- Input from devices and files is treated as untrusted: no shell command lines are built from it, paths are validated,
  and reports escape all content.
