#!/usr/bin/env bash
set -euo pipefail
PKG="$1"

adb root
sleep 2
if ! adb shell id | grep -q 'uid=0'; then
  echo "ERROR: adb root is not available; frida-server cannot attach" >&2
  exit 1
fi
adb wait-for-device shell 'while [ -z "$(getprop sys.boot_completed)" ]; do sleep 2; done'

echo "=== guest ABI ==="
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.product.cpu.abilist

FRIDA_VERSION=16.7.19
python3 - <<'PY'
import lzma, urllib.request
url = ("https://github.com/frida/frida/releases/download/"
       "16.7.19/frida-server-16.7.19-android-arm64.xz")
open("/tmp/frida-server", "wb").write(lzma.decompress(urllib.request.urlopen(url).read()))
PY
adb push /tmp/frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &'
sleep 5

python - <<'PY'
import zipfile
with zipfile.ZipFile("target.xapk") as archive:
    archive.extractall("work/splits")
PY
adb install-multiple work/splits/*.apk

adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1
sleep 40

echo "=== process check ==="
adb shell ps -A | grep -i "$PKG" || echo "NO PROCESS for $PKG"
echo "=== relevant logcat ==="
adb logcat -d -t 500 | grep -iE 'tempmail|pairip|FATAL|AndroidRuntime|dlopen|cannot find|abi' | tail -100 || true

.venv/bin/python -m pip install "frida==${FRIDA_VERSION}"
ok=0
for attempt in 1 2 3; do
  if .venv/bin/python -m dpairip.cli --capture "$PKG" -j work/junk_classes.txt -o work/pairip.json; then
    ok=1
    break
  fi
  sleep 15
done
test "$ok" -eq 1
test -s work/pairip.json
