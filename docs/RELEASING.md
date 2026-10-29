# Releasing

## A new version

1. Update `VERSION` in `scs/core.py` and the list in `CHANGELOG.md`.
2. Run the tests: `python3 -m pytest`.
3. Commit and push to `main`, then either push a tag (`git tag -a v0.2.1 -m "SCS Scanner 0.2.1" && git push origin v0.2.1`)
   or open *Actions › Release › Run workflow* – the workflow then creates the tag `v<VERSION>` itself.

The workflow `.github/workflows/release.yml` then builds everything reproducibly, signs a build provenance attestation
(Sigstore, no secret needed) and publishes the GitHub release with:

| File | What |
|---|---|
| `scs.pyz` | single-file version for Linux and macOS (`python3 scs.pyz`) |
| `scs.ps1` | PowerShell edition |
| `SCS-Scanner-<version>.zip` | complete program with launchers |
| `SCS-Scanner-Setup-<version>.exe` | Windows installer (PyInstaller + Inno Setup) |
| `sbom.cdx.json` | software bill of materials (CycloneDX) |
| `SHA256SUMS`, `ONE-LINERS.md` | checksums and copy-and-paste commands for this version |

4. Check the published release: download its files into one folder and run
   `python3 tools/verify_release.py FOLDER` (on the tagged commit). It confirms that the downloads contain exactly the
   source code and that `SHA256SUMS` and the SBOM match. The Windows installer is tested before it is published
   (`packaging/windows/test-installer.ps1`: install, self-test, window, uninstall) – CI runs the same test on every push.

## Code signing (recommended)

Unsigned Windows programs trigger SmartScreen warnings ("Windows protected your PC"), and some antivirus programs are
suspicious of security tools in general. Options:

- **SignPath Foundation** – free code signing for open-source projects (<https://signpath.org>), integrates with GitHub Actions.
- **Azure Trusted Signing** – inexpensive signing service for companies with a verified identity.
- **A classic OV/EV code signing certificate** from a certificate authority.

With a `.pfx` certificate, add the repository secrets `WINDOWS_SIGN_PFX_BASE64` (the file, Base64-encoded) and
`WINDOWS_SIGN_PASSWORD`; the release workflow then signs `SCS Scanner.exe` and the installer automatically.
The PowerShell edition can be signed with `Set-AuthenticodeSignature`; note that signing changes its checksum, so sign
before the checksums are written.

Signed git tags make releases traceable to the maintainer: `git config gpg.format ssh`,
`git config user.signingkey ~/.ssh/id_ed25519.pub`, then `git tag -s`.

## Repository settings (once, on GitHub)

- Settings › Code security: enable **private vulnerability reporting**, **Dependabot alerts**, **secret scanning** and
  **push protection**.
- Settings › Branches: protect `main` (pull requests required, status checks "CI" required, no force pushes).
- Settings › Actions: allow only actions that are pinned to a full commit SHA (all workflows here are).
