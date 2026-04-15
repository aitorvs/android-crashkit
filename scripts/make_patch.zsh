#!/usr/bin/env zsh
# make_patch.zsh
#
# Generate a numbered patch file from current edits in external/crashpad.
# The patch is saved to patches/crashpad/ and is ready to commit to this repo.
#
# Usage:
#   scripts/make_patch.zsh "short description of the change"
#
# Example:
#   scripts/make_patch.zsh "add exclude-annotation upload filter"
#   → patches/crashpad/0001-add-exclude-annotation-upload-filter.patch
#
# The description is used as the patch filename (spaces → hyphens, lowercased).
# Patches are numbered sequentially based on existing patches in the directory.
#
# To update an existing patch (e.g. after resolving a conflict with a new
# Crashpad version), delete the old patch file first, then re-run this script.

set -euo pipefail

SCRIPT_DIR="${0:a:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
PATCHES_DIR="${REPO_ROOT}/patches/crashpad"
CRASHPAD_DIR="${REPO_ROOT}/external/crashpad"

bold=$'\e[1m'; reset=$'\e[0m'
info()    { print -P "%F{blue}▸%f $*" }
success() { print -P "%F{green}✔%f $*" }
die()     { print -P "%F{red}✖%f $*" >&2; exit 1 }

[[ $# -lt 1 ]] && die "Usage: make_patch.zsh <description>"
[[ -d "$CRASHPAD_DIR/.git" ]] || die "Not a git repo: $CRASHPAD_DIR"

# ── Build output filename ─────────────────────────────────────────────────────
description="${*// /-}"       # spaces → hyphens
description="${description:l}" # lowercase
description="${description//[^a-z0-9-]/-}"  # strip non-alphanumeric except hyphens

existing=("${PATCHES_DIR}"/[0-9]*.patch(N))
next=$(( ${#existing[@]} + 1 ))
number=$(printf "%04d" "$next")
outfile="${PATCHES_DIR}/${number}-${description}.patch"

mkdir -p "$PATCHES_DIR"

# ── Stage all tracked modifications in crashpad ───────────────────────────────
git -C "$CRASHPAD_DIR" add -u

if git -C "$CRASHPAD_DIR" diff --cached --quiet; then
  die "Nothing staged in external/crashpad. Make your edits first."
fi

# ── Show what will be included ────────────────────────────────────────────────
echo
echo "${bold}Files to be patched:${reset}"
git -C "$CRASHPAD_DIR" diff --cached --name-only | sed 's/^/  /'
echo

# ── Write the patch ───────────────────────────────────────────────────────────
git -C "$CRASHPAD_DIR" diff --cached > "$outfile"

# Unstage (leave working tree intact so the dev can keep iterating)
git -C "$CRASHPAD_DIR" reset HEAD -- . 2>/dev/null || true

success "Patch created: patches/crashpad/${number}-${description}.patch"
echo
info "Next steps:"
echo "  1. Review the patch:   cat patches/crashpad/${number}-${description}.patch"
echo "  2. Test it applies:    scripts/apply_patches.zsh"
echo "  3. Commit to crashkit: git add patches/crashpad/${number}-${description}.patch"
echo
info "To rebuild with the patch applied, run:"
echo "  scripts/update_crashpad.zsh --skip-bootstrap"
