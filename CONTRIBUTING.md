# Contributing

Thank you for helping. Bug reports, new checks and translations are welcome.

## Ground rules

- The scanner is for checking **your own devices** or devices whose owner agreed. Contributions that help to spy on
  other people, hide from their owners or bypass consent will not be accepted.
- **Never commit real malware, real indicator files or personal data.** Tests use synthetic data only:
  domains under `.example`, IP addresses from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and harmless text files.
- The Python code uses the standard library only. Optional extras must stay optional.
- Code, comments, messages and documentation are written in English.
- `powershell/scs.ps1` must stay ASCII-only and compatible with Windows PowerShell 5.1.

## Development

```sh
python3 -m pip install --require-hashes -r requirements/test.txt -r requirements/lint.txt   # Python 3.10+
python3 -m pytest              # also runs the PowerShell tests when pwsh is installed
ruff check scs tools tests
python3 tools/build_release.py # builds dist/ reproducibly
```

## Pull requests

Describe what the change detects or fixes and how you tested it. New checks need a test with synthetic data and must
report their result honestly (`DETECTED` only for indicator matches, `WARNING` for heuristics, `NOT CHECKED` when a
check could not run).
