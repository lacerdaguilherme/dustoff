# Writing rules

Rules are TOML. The built-in ones live in [`rules/default.toml`](../rules/default.toml);
yours go in `~/.config/dustoff/rules.d/*.toml` (same `id` overrides a built-in one).

```toml
[[rule]]
id = "uv-cache"                  # unique
name = "uv cache"                # shown in the table
category = "dev-cache"
risk = "safe"                    # safe | review (review is never picked by "all")
paths = ["~/.cache/uv"]          # globs, must start with ~/ and stay inside $HOME
regrows = "Next `uv run` downloads wheels again."
skip_if_running = ["uv", "uvx"]  # /proc comm names; rule is skipped while they run
clean_command = ["uv", "cache", "clean"]  # preferred over deleting files, if on PATH
```

Guidelines:

* Prefer the tool's own cleanup command (`clean_command`) over deleting files.
* `safe` only when the tool recreates the data by itself and you only lose time.
  Anything that can hold your work or settings is `review`.
* Paths must be at least two levels below `$HOME`; dustoff refuses anything else.

## Known apps (`rules/apps.toml`)

Maps an application to the directories it uses and to the names that prove it is
installed (package, binary, `/opt` dir, Flatpak id, Snap, AppImage). When none is
found, its directories are reported as orphaned with high confidence.
