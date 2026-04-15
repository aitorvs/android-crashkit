#!/usr/bin/env zsh
set -euo pipefail

API_LEVEL=26
IS_DEBUG=false
IS_COMPONENT=false
USE_CUSTOM_LIBCXX=false
EXTRA_LDFLAGS="-static-libstdc++"
OUTROOT="out"
CLEAN=false
ASAN=false
ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

usage() {
  cat <<EOF
Usage: $0 [--abis "arm64-v8a x86 x86_64"] [--api 26] [--out out] [--clean] [--asan]
          [--ndk /path/to/ndk] [--extra-ldflags "..."]
EOF
}

NDK_PATH="${NDK:-${ANDROID_NDK_HOME:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --abis)
      # Split on commas or spaces (zsh-safe)
      local abistr="${2//,/ }"
      ABIS=(${=abistr})
      shift 2 ;;
    --api)             API_LEVEL="$2"; shift 2 ;;
    --out)             OUTROOT="$2"; shift 2 ;;
    --clean)           CLEAN=true; shift ;;
    --asan)            ASAN=true; shift ;;
    --extra-ldflags)   EXTRA_LDFLAGS="$2"; shift 2 ;;
    --ndk)             NDK_PATH="$2"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

# Auto-discover NDK if needed
if [[ -z "${NDK_PATH}" ]]; then
  if [[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME}/ndk" ]]; then
    NDK_PATH=$(ls -d "${ANDROID_HOME}/ndk/"* 2>/dev/null | sort -V | tail -n1)
  fi
fi
[[ -n "${NDK_PATH}" && -d "${NDK_PATH}" ]] || { echo "NDK not found. Pass --ndk or set \$NDK / \$ANDROID_NDK_HOME"; exit 1; }

typeset -A CPU_FOR_ABI OUT_FOR_ABI
CPU_FOR_ABI=(
  arm64-v8a arm64
  armeabi-v7a arm
  x86 x86
  x86_64 x64
)
OUT_FOR_ABI=(
  arm64-v8a android-arm64
  armeabi-v7a android-arm
  x86 android-x86
  x86_64 android-x64
)

for abi in "${ABIS[@]}"; do
  cpu="${CPU_FOR_ABI[$abi]:-}"
  out="${OUT_FOR_ABI[$abi]:-}"
  [[ -n "$cpu" && -n "$out" ]] || { echo "Unsupported ABI: $abi"; exit 1; }

  OUTDIR="${OUTROOT}/${out}"
  $CLEAN && { echo "gn clean ${OUTDIR}"; gn clean "${OUTDIR}" || true; }

  IS_ASAN=$([[ $ASAN == true ]] && echo true || echo false)

  ARGS=(
    target_os=\"android\"
    target_cpu=\"${cpu}\"
    is_debug=${IS_DEBUG}
    use_custom_libcxx=${USE_CUSTOM_LIBCXX}
    android_api_level=${API_LEVEL}
    android_ndk_root=\"${NDK_PATH}\"
    extra_ldflags=\"${EXTRA_LDFLAGS}\"
  )
  # (Note: 'is_asan' isn't a Crashpad arg; omit to avoid GN warnings.)

  echo "gn gen ${OUTDIR} --args='${(j: :)ARGS}'"
  gn gen "${OUTDIR}" --args="${(j: :)ARGS}"
done

echo "Done gn gen for: ${ABIS[*]}"

