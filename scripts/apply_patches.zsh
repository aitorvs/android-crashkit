#!/usr/bin/env zsh
# apply_patches.zsh
#
# Apply all crashpad patches in lexicographic order.
# Called automatically by update_crashpad.zsh after gclient sync.
# Can also be run standalone:
#
#   scripts/apply_patches.zsh [--crashpad-dir <path>]

set -euo pipefail

SCRIPT_DIR="${0:a:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
PATCHES_DIR="${REPO_ROOT}/patches/crashpad"

bold=$'\e[1m'; reset=$'\e[0m'
info()    { print -P "%F{blue}▸%f $*" }
success() { print -P "%F{green}✔%f $*" }
warn()    { print -P "%F{yellow}⚠%f $*" }
die()     { print -P "%F{red}✖%f $*" >&2; exit 1 }

# ── Argument parsing ──────────────────────────────────────────────────────────
CRASHPAD_DIR="${REPO_ROOT}/external/crashpad"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --crashpad-dir) CRASHPAD_DIR="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ -d "$CRASHPAD_DIR" ]] || die "Crashpad dir not found: $CRASHPAD_DIR"
[[ -d "$CRASHPAD_DIR/.git" ]] || die "Not a git repo: $CRASHPAD_DIR"

# ── Collect patches ───────────────────────────────────────────────────────────
patches=("${PATCHES_DIR}"/[0-9]*.patch(N))
if [[ ${#patches[@]} -eq 0 ]]; then
  info "No patches to apply."
  exit 0
fi

info "Applying ${#patches[@]} patch(es) to ${CRASHPAD_DIR}..."

# ── Apply each patch ──────────────────────────────────────────────────────────
for patch in "${patches[@]}"; do
  name="${patch:t}"

  # Already applied? (reverse-check — silent)
  if git -C "$CRASHPAD_DIR" apply --check --reverse "$patch" 2>/dev/null; then
    info "Already applied: ${name}"
    continue
  fi

  # Applies cleanly?
  if git -C "$CRASHPAD_DIR" apply --check "$patch" 2>/dev/null; then
    git -C "$CRASHPAD_DIR" apply "$patch"
    success "Applied: ${name}"
    continue
  fi

  # Try 3-way merge (requires index; works after gclient sync leaves a clean tree)
  warn "Patch does not apply cleanly, trying 3-way merge: ${name}"
  if git -C "$CRASHPAD_DIR" apply --3way "$patch" 2>/dev/null; then
    # Check for leftover conflict markers
    if git -C "$CRASHPAD_DIR" diff --check 2>/dev/null; then
      warn "Applied via 3-way merge (verify the result): ${name}"
      continue
    fi
  fi

  # Unresolvable — prompt the developer
  echo
  echo "${bold}Conflict: ${name}${reset}"
  echo "The patch could not be applied cleanly against the current Crashpad tree."
  echo "This usually means Crashpad was updated and the patched code changed."
  echo
  echo "Options:"
  echo "  s) Skip this patch and continue (the feature it provides will be missing)"
  echo "  a) Abort — stop here so you can resolve the conflict manually"
  printf "Choice [s/a]: "
  read -r choice
  case "${choice:l}" in
    s)
      warn "Skipped: ${name}"
      warn "Remember to regenerate this patch after resolving the conflict."
      warn "Run: scripts/make_patch.zsh after editing the files in ${CRASHPAD_DIR}"
      ;;
    *)
      echo
      echo "To resolve:"
      echo "  1. Edit the conflicting files in: ${CRASHPAD_DIR}"
      echo "  2. Regenerate the patch:  scripts/make_patch.zsh <description>"
      echo "  3. Replace patches/crashpad/${name} with the new patch"
      echo "  4. Re-run: scripts/update_crashpad.zsh --skip-bootstrap"
      die "Aborted at ${name}."
      ;;
  esac
done

success "Patch step complete."
