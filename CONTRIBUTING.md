# Contributing

Thanks for helping. The most useful contribution is a **new rule** or a
**new known app**: see [docs/writing-rules.md](docs/writing-rules.md).

Code changes: `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and
`cargo test` must pass. Anything that deletes files needs a test showing what it
refuses to delete.

Safety is the product. A change that makes dustoff delete more, or delete
without showing and asking first, will not be merged.
