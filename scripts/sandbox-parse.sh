#!/usr/bin/env bash
# Run the parser on untrusted input inside a locked-down systemd service.
#
# The service has its own network namespace with no interfaces, an unprivileged
# user, a read-only view of the filesystem, no capabilities, a syscall filter
# and hard resource limits. It can write to the output directory and nowhere
# else. The parser also checks for itself that it has no network and refuses to
# start if it does.
#
# Usage (as root): sandbox-parse.sh <code-dir> <input-dir> <output-dir>
set -euo pipefail

SRC="$(realpath "${1:?code directory}")"
IN_SRC="$(realpath "${2:?input directory}")"
OUT_DST="$(realpath "${3:?output directory}")"

# Work from root-owned copies outside /home, which the sandbox cannot see.
BASE="$(mktemp -d /srv/vi-XXXXXX)"
trap 'rm -rf "$BASE"' EXIT
mkdir -p "$BASE/app" "$BASE/in" "$BASE/out"
cp -r "$SRC/pipeline" "$BASE/app/pipeline"
cp -r "$IN_SRC/." "$BASE/in/"
find "$BASE/in" -type l -delete
chown -R root:root "$BASE"
chmod -R a+rX,go-w "$BASE"
chown nobody:nogroup "$BASE/out"
chmod 0700 "$BASE/out"

status=0
systemd-run --quiet --wait --collect --pipe \
  --unit "vi-parse-$$" \
  -p User=nobody -p Group=nogroup \
  -p WorkingDirectory="$BASE/app" \
  -p PrivateNetwork=yes \
  -p RestrictAddressFamilies=AF_UNIX \
  -p ProtectSystem=strict \
  -p ProtectHome=yes \
  -p PrivateTmp=yes \
  -p PrivateDevices=yes \
  -p ReadWritePaths="$BASE/out" \
  -p NoNewPrivileges=yes \
  -p CapabilityBoundingSet= \
  -p AmbientCapabilities= \
  -p RestrictNamespaces=yes \
  -p RestrictSUIDSGID=yes \
  -p RestrictRealtime=yes \
  -p LockPersonality=yes \
  -p MemoryDenyWriteExecute=yes \
  -p ProtectKernelTunables=yes \
  -p ProtectKernelModules=yes \
  -p ProtectKernelLogs=yes \
  -p ProtectControlGroups=yes \
  -p ProtectHostname=yes \
  -p ProtectProc=invisible \
  -p SystemCallArchitectures=native \
  -p SystemCallFilter=@system-service \
  -p SystemCallErrorNumber=EPERM \
  -p UMask=0077 \
  -p MemoryMax=3G \
  -p TasksMax=64 \
  -p LimitNOFILE=1024 \
  -p RuntimeMaxSec=600 \
  -E PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B -m pipeline.parse --in "$BASE/in" --out "$BASE/out" --require-sandbox \
  || status=$?

# Hand back only the two expected regular files; ignore anything else.
mkdir -p "$OUT_DST"
for name in observations.jsonl parse-report.json; do
  if [ -f "$BASE/out/$name" ] && [ ! -L "$BASE/out/$name" ]; then
    install -m 0644 "$BASE/out/$name" "$OUT_DST/$name"
  fi
done
exit "$status"
