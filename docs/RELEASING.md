# Releasing

## A new version

1. Update `VERSION` in `scs/core.py` and the list in `CHANGELOG.md`.
2. Run the tests: `python3 -m pytest`.
3. Commit and push to `main`, then either push a tag (`git tag -a v0.2.1 -m "SCS Scanner 0.2.1" && git push origin v0.2.1`)
   or open *Actions › Release › Run workflow* – the workflow then creates the tag `v<VERSION>` itself.

The workflow `.github/workflows/release.yml` then

1. runs the tests, builds everything reproducibly, signs a build provenance attestation (Sigstore, no secret needed)
   and creates a **draft** release,
2. builds the Windows installer, tests it (`packaging/windows/test-installer.ps1`: install, self-test, window,
   uninstall) and adds it to the draft,
3. downloads every file of the draft, checks it against the source with `tools/verify_release.py` and only then
   **publishes** the release. Nothing half-finished or unchecked is ever visible.

With *immutable releases* enabled (Settings › General › Releases), the tag and the files of a published release can
never be changed or deleted afterwards – not even with stolen credentials. A mistake is fixed with a new version.

| File | What |
|---|---|
| `scs.pyz` | single-file version for Linux and macOS (`python3 scs.pyz`) |
| `scs.ps1` | PowerShell edition |
| `SCS-Scanner-<version>.zip` | complete program with launchers |
| `SCS-Scanner-Setup-<version>.exe` | Windows installer (PyInstaller + Inno Setup) |
| `sbom.cdx.json` | software bill of materials (CycloneDX) |
| `SHA256SUMS`, `ONE-LINERS.md` | checksums and copy-and-paste commands for this version |
| `*-provenance.sigstore.json` | signed build provenance of the program files and of the installer (Sigstore bundles) |

Anyone can repeat the check later: download the files into one folder and run `python3 tools/verify_release.py FOLDER`
on the tagged source (see SECURITY.md).

## Tools used by CI and the release

pytest, ruff, zizmor and PyInstaller are installed only from hash-pinned lock files (`requirements/*.txt`,
`packaging/windows/requirements.txt`). To update one, change the version in the `.in` file next to it and run the
command in the first lines of the `.txt` file (needs `uv`). GitHub Actions are pinned to commit hashes; Dependabot
proposes updates a week after they appear – check that the new hash belongs to the release tag before merging.

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

## Repository settings (set on GitHub)

- Security: private vulnerability reporting, Dependabot alerts and security updates, secret scanning with push
  protection, code scanning (CodeQL workflow), OpenSSF Scorecard.
- Rules: `main` cannot be force-pushed or deleted; release tags `v*` cannot be moved or deleted.
- Releases: immutable releases.
- Actions: workflows get a read-only token by default and cannot approve pull requests; workflows of all external
  contributors need approval; only actions by GitHub and `ossf/scorecard-action`, each pinned to a full commit SHA,
  may run (a new third-party action has to be added to the list in Settings › Actions first).
- Pushes: at most 5 branches or tags can be changed in one push.
- Maintainer account: two-factor authentication with a passkey or security key; review SSH keys, tokens, authorized
  apps and sessions twice a year.
