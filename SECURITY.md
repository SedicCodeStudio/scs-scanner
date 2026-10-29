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
shasum -a 256 -c SHA256SUMS            # Linux / macOS (lists a missing file for each one you did not download)
gh attestation verify scs.pyz --repo SedicCodeStudio/scs-scanner
```

From version 0.2.1 on, the signed provenance is also attached to each release as a file
(`SCS-Scanner-<version>-provenance.sigstore.json`, `SCS-Scanner-Setup-<version>-provenance.sigstore.json`), so the
check does not need the GitHub API: `gh attestation verify scs.pyz --repo SedicCodeStudio/scs-scanner --bundle FILE`.

```powershell
Get-FileHash .\scs.ps1 -Algorithm SHA256   # compare with SHA256SUMS
```

**Check that a release contains exactly the published source code** – put the downloaded files into one folder and run:

```sh
git clone https://github.com/SedicCodeStudio/scs-scanner && cd scs-scanner
git worktree add ../scs-v0.2.0 v0.2.0                        # the source of the version you downloaded
python3 tools/verify_release.py ~/Downloads/scs --source ../scs-v0.2.0
```

The tool rebuilds the release from that source and compares every file inside `scs.pyz` and the ZIP, `scs.ps1` byte
for byte, the SBOM and `SHA256SUMS`. The build is reproducible (fixed timestamps, order and permissions); `scs.ps1` is
always byte-identical, and the archives are too when they are compressed by the same zlib version as on the GitHub
runner – which is why the tool compares the files inside them rather than the compressed bytes.
The Windows installer cannot be rebuilt byte for byte; its checksum and the build provenance attestation cover it.

Each release also contains a software bill of materials (`sbom.cdx.json`, CycloneDX 1.5) that lists every part of the
release and where third-party components come from.

## Design principles

- Read-only by default. Nothing is deleted without an explicit confirmation; the quarantine moves files, it never deletes them.
- No telemetry. The only network requests are the downloads of the indicator lists (and optionally the YARA rules)
  from their public sources over HTTPS. Reports stay on your computer.
- No third-party Python packages are required; optional extras are clearly marked.
- Input from devices and files is treated as untrusted: no shell command lines are built from it, paths are validated,
  and reports escape all content.
