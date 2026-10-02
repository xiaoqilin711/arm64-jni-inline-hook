#!/usr/bin/env bash
#
# Cross-compile the hook core and the example injection .so for arm64-v8a.
#
# Usage:
#   NDK=/path/to/ndk ./build.sh            # full NDK path
#   ./build.sh                             # tries $ANDROID_NDK_HOME / $NDK
#
# Outputs (into build/):
#   libjnihook.so            — the framework core
#   libresource_api_dump.so  — the example injection .so (link or copy into
#                              your target app's injection dir)
set -euo pipefail

API=24
ARCH=aarch64-linux-android

NDK="${NDK:-${ANDROID_NDK_HOME:-}}"
if [ -z "$NDK" ]; then
  echo "error: set NDK to your Android NDK root" >&2
  exit 1
fi

CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/${ARCH}${API}-clang"
# Fall back to the Windows prebuilt if the Linux one is absent (Git Bash / WSL).
[ -x "$CLANG" ] || CLANG="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/${ARCH}${API}-clang.exe"
[ -x "$CLANG" ] || { echo "error: clang not found under $NDK" >&2; exit 1; }

mkdir -p build

echo ">> building libjnihook.so (core)"
"$CLANG" -shared -fPIC -O2 -Iinclude \
  src/jnihook.c \
  -o build/libjnihook.so \
  -llog

echo ">> building libresource_api_dump.so (example)"
"$CLANG" -shared -fPIC -O2 -Iinclude \
  examples/resource_api_dump.c src/jnihook.c \
  -o build/libresource_api_dump.so \
  -llog

echo ">> done. artifacts in build/"
ls -la build/
