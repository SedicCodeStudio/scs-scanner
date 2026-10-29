"""Writes the Windows version resource (file properties: company, product, version) for PyInstaller."""
import sys

TEMPLATE = """VSVersionInfo(
  ffi=FixedFileInfo(filevers=({a}, {b}, {c}, 0), prodvers=({a}, {b}, {c}, 0), mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Sedic Code Studio'),
      StringStruct('FileDescription', 'SCS Scanner - checks your devices for spyware and malware'),
      StringStruct('FileVersion', '{v}'),
      StringStruct('InternalName', 'SCS Scanner'),
      StringStruct('LegalCopyright', 'Copyright 2026 Sedic Code Studio. Apache License 2.0.'),
      StringStruct('OriginalFilename', 'SCS Scanner.exe'),
      StringStruct('ProductName', 'SCS Scanner'),
      StringStruct('ProductVersion', '{v}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""

if __name__ == "__main__":
    version, out = sys.argv[1], sys.argv[2]
    a, b, c = (int(x) for x in version.split(".")[:3])
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE.format(a=a, b=b, c=c, v=version))
