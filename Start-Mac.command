#!/bin/sh
# Double-click in Finder to start SCS Scanner. The first time: right-click > Open, because the file comes from the internet.
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  osascript -e 'display dialog "SCS Scanner needs Python 3. Install it from python.org (recommended) or run: xcode-select --install" buttons {"OK"} default button 1' >/dev/null 2>&1
  exit 1
fi
exec python3 scs.py "$@"
