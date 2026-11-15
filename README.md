# dustoff

Find and safely remove the stuff that quietly eats your disk: package caches,
build artifacts, leftover config of apps you uninstalled long ago.

**It never deletes anything without showing it first and asking you to confirm.**

```text
$ dustoff scan --orphans --projects ~/code
  #        SIZE  RISK    WHAT                                  ACTION / PATH
  1     4.0 GiB  safe    Chrome on-device AI model             delete  ~/.config/google-chrome/OptGuideOnDeviceModel
  2     1.4 GiB  safe    npm cache                             run `npm cache clean --force`  ~/.npm/_cacache
  3   235.3 MiB  review  Antigravity data                      delete  ~/.config/Antigravity
                                                               note: unknown owner: no package, binary, flatpak, ...
  4    44.4 MiB  review  Capacities data                       delete  ~/.config/Capacities
                                                               note: Capacities is not installed (checked deb, flatpak, ...)
```

## Safety model

* `scan` is read-only. `clean --dry-run` prints the plan and stops.
* `clean` shows every item, lets you pick, shows the final list with the exact
  action, and only proceeds if you type `yes`. No `--yes` flag, and it refuses to
  run without an interactive terminal.
* Only paths inside `$HOME`, at least two levels deep, are ever touched, after
  resolving symlinks in parent directories (a symlink pointing outside your home
  is refused). A symlink that is itself the target is removed, never followed.
  Credentials and key material (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
  keyrings, ...) are never targets, and dustoff refuses to run as root.
* Rules you add yourself are untrusted: they always count as `review`, are
  labelled `[user rule]`, and may not use shells or interpreters as commands.
* Names shown in the terminal have control characters stripped, so a hostile
  directory name cannot forge the list you confirm.
* Items marked `review` (your trash, ML models, orphaned app data) are never
  selected by `all`; you must pick them by number.
* Caches of a running app are skipped (`'chrome' is running`).
* When a tool has its own cleanup command (`uv cache clean`, `npm cache clean`,
  `go clean -cache`, `pnpm store prune`, ...), dustoff runs that instead of
  deleting files. They run from your home directory with a minimal environment,
  so redirected cache variables cannot point them elsewhere. `--no-commands`
  forces direct deletion. Sizes are disk usage (hard links counted once).

## What it finds

| Source | Flag | Examples |
| --- | --- | --- |
| Cache rules | always | uv, pip, npm, pnpm, yarn, Go, Cargo, Gradle, Terraform, conda, browsers, VS Code, thumbnails, trash |
| Build artifacts | `--projects PATH` | `node_modules`, `target`, `.terraform`, `.venv`, `__pycache__` (only next to the file that proves it is a project) |
| Orphaned app data | `--orphans` | config/data/cache dirs of apps that are no longer installed, checked against deb, Flatpak, Snap, `PATH`, `/opt`, AppImages and `.desktop` files |

Orphan hits come with a confidence: **high** for apps in
[`rules/apps.toml`](rules/apps.toml) (name known, no install evidence), **low**
for unknown directories in `~/.config`, `~/.local/share`, `~/.cache`
(a directory name is only a hint). Low-confidence hits touched in the last 30
days are hidden.

## Usage

```bash
dustoff scan                       # what is there
dustoff scan --json                # same, machine readable
dustoff clean --dry-run            # plan only
dustoff clean                      # plan, pick, confirm, delete
dustoff clean --projects ~/code --older-than 60 --orphans
dustoff rules                      # list active rules
```

## Install

```bash
cargo install --git https://github.com/lacerdaguilherme/dustoff
```

Linux first; macOS is on the roadmap (see issues).

## Extending

Rules are plain TOML, see [docs/writing-rules.md](docs/writing-rules.md).
Drop your own in `~/.config/dustoff/rules.d/`.

## Roadmap

Tracked in [milestones](https://github.com/lacerdaguilherme/dustoff/milestones):
duplicate and large-file finder, quarantine instead of delete, unused-app
detection, JSON report, then a graphical front end on the same library.

## Credits

Inspired by [BleachBit](https://github.com/bleachbit/bleachbit),
[czkawka](https://github.com/qarmin/czkawka),
[kondo](https://github.com/tbillington/kondo),
[dust](https://github.com/bootandy/dust) and
[npkill](https://github.com/voidcosmos/npkill). All rules here are written from
scratch; no code or rule data was copied from those projects.

## License

MIT
