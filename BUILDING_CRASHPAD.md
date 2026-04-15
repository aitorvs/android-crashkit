# Building Crashpad for crashkit

This document covers how to update the vendored Crashpad artifacts inside the `crashkit` library module. You only need to do this when upgrading Crashpad to a newer version.

The pre-built artifacts already in the repo are enough to build and publish `crashkit` — skip straight to **Publishing crashkit** if you're not updating Crashpad.

---

## Quick path — automated script

`scripts/update_crashpad.zsh` runs all four steps (sync → build → vendor → publish) end-to-end with interactive prompts and sensible defaults:

```bash
scripts/update_crashpad.zsh
```

Or fully non-interactive:

```bash
scripts/update_crashpad.zsh \
  --crashpad-dir external/crashpad \
  --ndk "$NDK" \
  --version 0.0.3-SNAPSHOT \
  -y
```

Pass `--skip-bootstrap` if Crashpad is already synced and you only want to rebuild (patches will still be applied). Pass `--skip-publish` to vendor artifacts without publishing. Run with `--help` for all options.

The manual steps below document what the script does under the hood.

---

## Local patches to Crashpad

The `patches/crashpad/` directory contains patches that are applied to Crashpad before every build. They add functionality not present upstream (e.g. annotation allowlisting for PII control).

**Patches are applied automatically** by `update_crashpad.zsh` between sync and build. You don't need to apply them manually.

### Adding a new patch

Make your edits inside `external/crashpad/`, then run:

```bash
scripts/make_patch.zsh "short description of the change"
# → patches/crashpad/0002-short-description-of-the-change.patch
```

Commit the generated `.patch` file to this repo. The working tree in `external/crashpad/` is not committed — only the patch is.

### Handling a conflict after a Crashpad update

If `update_crashpad.zsh` reports a conflict on a patch, abort when prompted, then:

1. Manually re-apply and resolve the conflict in `external/crashpad/`
2. Regenerate the patch: `scripts/make_patch.zsh "same description"`
3. Replace the old patch file with the new one
4. Re-run: `scripts/update_crashpad.zsh --skip-bootstrap`

---

## Prerequisites

- **macOS or Linux** — Crashpad's Android cross-compilation works on both; Linux is slightly smoother.
- **Python 3** — required by `depot_tools`.
- **Android NDK** — tested with NDK `28.2.13676358`. Set the `NDK` environment variable to its path:
  ```bash
  export NDK="$HOME/Library/Android/sdk/ndk/28.2.13676358"
  ```
- **`depot_tools`** — the bootstrap script will fetch it for you.
- **`gn` and `ninja`** — installed by `depot_tools`.

---

## Step 1 — Bootstrap Crashpad (first time only)

Fetch `depot_tools`, clone Crashpad, and sync all its dependencies:

```bash
scripts/bootstrap_crashpad.zsh \
  --dest external/crashpad \
  --ndk "$NDK"
```

This is safe to re-run — it won't reclone if the directory already exists.

To update an existing checkout to the latest `main`:

```bash
cd external/crashpad
git pull --rebase
cd ..
gclient sync -D
```

---

## Step 2 — Build Crashpad for all ABIs

Run from the **repo root** (not from inside the Crashpad directory):

```bash
export NDK="$HOME/Library/Android/sdk/ndk/28.2.13676358"

cd external/crashpad
../../scripts/crashpad_all.zsh \
  --abis "arm64-v8a armeabi-v7a x86 x86_64" \
  --api 26 \
  --out out
```

This runs `gn gen` + `ninja` for each ABI. The GN args used are:

| Arg | Value | Why |
|---|---|---|
| `target_os` | `android` | Android cross-compilation |
| `target_cpu` | per ABI | `arm64`, `arm`, `x86`, `x64` |
| `is_debug` | `false` | Release build, no debug info |
| `is_component_build` | `false` | Static `.a` libs, not `.so` |
| `use_custom_libcxx` | `false` | Use NDK's libc++, not Crashpad's bundled one |
| `android_api_level` | `26` | Match DDG's minSdk |
| `android_ndk_root` | `$NDK` | Path to the NDK |
| `extra_ldflags` | `-static-libstdc++` | Statically link C++ runtime into the handler |

Artifacts produced per ABI (in `external/crashpad/out/android-<cpu>/`):

```
crashpad_handler                                              ← handler subprocess (ELF)
obj/client/libclient.a
obj/client/libcommon.a
obj/util/libutil.a
obj/third_party/mini_chromium/mini_chromium/base/libbase.a
```

---

## Step 3 — Copy artifacts into crashkit

```bash
# Back in repo root
scripts/copy_crashpad_static_libs.sh \
  --src external/crashpad/out \
  --dst crashkit/src/main/cpp/crashpad/ \
  --hdr-src external/crashpad \
  --abis "arm64-v8a armeabi-v7a x86 x86_64"
```

This overwrites all `.a` files, all `crashpad_handler.so` files, and the headers under `crashkit/src/main/cpp/crashpad/include/`.

Verify the handler is an Android ELF (not a macOS binary):

```bash
file crashkit/src/main/cpp/crashpad/lib/arm64-v8a/crashpad_handler.so
# Should say: ELF 64-bit LSB shared object, ARM aarch64
```

---

## Step 4 — Check for API breakage

Crashpad doesn't have a stable public API. After copying new headers, try to build:

```bash
./gradlew :crashkit:assembleRelease
```

If there are compile errors in `native-bridge.cpp`, check the Crashpad changelog or the header diff for the affected symbols (`CaptureContext`, `SetFirstChanceExceptionHandler`, `CrashpadInfo`, etc.) and update accordingly.

---

## Step 5 — Publish crashkit

Bump the version and publish to Maven local (or remote):

```bash
./gradlew :crashkit:publishToMavenLocal -PVERSION_NAME=<new-version>
```

Then update the dependency version in the DDG Android app's `build.gradle`.

---

## Troubleshooting

**`ninja: unknown target '/handler:crashpad_handler'`**
Use `crashpad_all.zsh` — it invokes Ninja by artifact paths, not GN labels, which avoids this.

**`/proc/self/fd/1` FileNotFoundError on macOS**
Use `ninja` directly (not `autoninja`). The scripts already do this.

**`ndkVersion` mismatch in Gradle**
The NDK used to build Crashpad should match the `ndkVersion` set in `crashkit/build.gradle`. Mismatches can cause subtle ABI issues.

**Handler is a macOS binary instead of ELF**
You built on macOS without a proper Android cross-compilation setup. Use Linux, or verify your NDK/GN target args are correct.

---

## Script reference

| Script | Purpose |
|---|---|
| `scripts/update_crashpad.zsh` | **End-to-end**: sync → patch → build → vendor → publish |
| `scripts/apply_patches.zsh` | Apply all patches in `patches/crashpad/` to the Crashpad tree |
| `scripts/make_patch.zsh` | Generate a new numbered patch from edits in `external/crashpad/` |
| `scripts/bootstrap_crashpad.zsh` | Fetch depot_tools + clone/sync Crashpad |
| `scripts/crashpad_gn.zsh` | Run `gn gen` for one or more ABIs |
| `scripts/crashpad_build.zsh` | Run `ninja` for one or more ABIs |
| `scripts/crashpad_all.zsh` | `gn gen` + `ninja` in one step |
| `scripts/copy_crashpad_static_libs.sh` | Copy handler + `.a` libs into the library module |
