# scripts/

Helper scripts for fetching, building, and vendoring Crashpad into the `crashkit` library module.

For the full step-by-step guide see **[BUILDING_CRASHPAD.md](../BUILDING_CRASHPAD.md)**.

---

| Script | Purpose |
|---|---|
| `update_crashpad.zsh` | **End-to-end**: sync → patch → build → vendor → publish (use this normally) |
| `apply_patches.zsh` | Apply all patches in `patches/crashpad/` to the Crashpad tree |
| `make_patch.zsh` | Generate a new numbered patch from edits in `external/crashpad/` |
| `bootstrap_crashpad.zsh` | Clone Crashpad + depot_tools and sync all dependencies |
| `crashpad_gn.zsh` | Run `gn gen` for one or more Android ABIs |
| `crashpad_build.zsh` | Run `ninja` for one or more Android ABIs |
| `crashpad_all.zsh` | `gn gen` + `ninja` in one step |
| `copy_crashpad_static_libs.sh` | Copy handler + static libs into `crashkit/src/main/cpp/crashpad/lib/` |
