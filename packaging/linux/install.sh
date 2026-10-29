#!/bin/sh
# Installs SCS Scanner for the current user (no root needed):
#   program  ~/.local/share/scs-scanner     command  ~/.local/bin/scs     menu entry  "SCS Scanner"
# Run from the unpacked release folder:   sh packaging/linux/install.sh        Remove again:   sh packaging/linux/install.sh --uninstall
set -eu
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APP="$DATA/scs-scanner"
BIN="$HOME/.local/bin"
DESKTOP="$DATA/applications/scs-scanner.desktop"

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$APP" "$BIN/scs" "$DESKTOP"
  echo "SCS Scanner removed. Reports, change history and quarantine in ~/.scs-scanner were kept."
  exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required: sudo apt install python3 (or the package manager of your system)"; exit 1; }
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$SRC/scs/cli.py" ] || { echo "Run this script from the unpacked SCS Scanner folder."; exit 1; }

rm -rf "$APP"
mkdir -p "$APP" "$BIN" "$(dirname "$DESKTOP")"
cp -R "$SRC/scs" "$SRC/scs.py" "$SRC/LICENSE" "$SRC/NOTICE" "$APP/"
cp "$SRC/packaging/linux/scs.png" "$APP/scs.png"
cat > "$BIN/scs" <<WRAP
#!/bin/sh
exec python3 "$APP/scs.py" "\$@"
WRAP
chmod 755 "$BIN/scs"
cat > "$DESKTOP" <<ENTRY
[Desktop Entry]
Type=Application
Name=SCS Scanner
Comment=Check this computer for spyware, malware and hidden files
Exec=python3 "$APP/scs.py"
Icon=$APP/scs.png
Terminal=false
Categories=System;Security;Utility;
ENTRY
python3 -c "import tkinter" 2>/dev/null || echo "Note: the window needs Tkinter – sudo apt install python3-tk (the command line works without it)."
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Note: add $BIN to your PATH to use the command \"scs\"." ;; esac
echo "SCS Scanner installed. Start it from the application menu or with: scs"
