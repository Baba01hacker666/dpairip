#!/usr/bin/env bash
set -euo pipefail
PKG="$1"

adb root
sleep 2
if ! adb shell id | grep -q 'uid=0'; then
  echo "ERROR: adb root is not available; frida-server cannot attach" >&2
  exit 1
fi

# Frida 16.x still has the Java bridge; 17.x removed it.
FRIDA_VERSION=16.7.19
curl -L -o /tmp/frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
xz -dc /tmp/frida-server.xz > /tmp/frida-server
adb push /tmp/frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &'
sleep 2

# Install the ORIGINAL signed splits -- do not install the merged/patched APK.
python - <<'PY'
import zipfile
with zipfile.ZipFile("target.xapk") as archive:
    archive.extractall("work/splits")
PY
adb install-multiple work/splits/*.apk

adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1
sleep 20   # let PairIP finish VM init and populate the junk fields

python -m pip install "frida==${FRIDA_VERSION}"
python -m dpairip.cli --capture "$PKG" -j work/junk_classes.txt -o work/pairip.json
test -s work/pairip.json
