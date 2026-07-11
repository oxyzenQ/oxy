# Zelynic Project Rules

## File Size

- Core/code files must stay under `1000` lines of code.
- This applies to source and core files such as `*.rs`, `*.c`, `*.h`, `*.css`,
  `*.py`, and `*.sh`.
- This excludes `*.md`, `*.txt`, generated files, lockfiles, assets, release
  artifacts, `.git/`, and `target/`.
- `src/main.rs` has a soft target of `100-300` LOC in a mature project and
  should remain bootstrap/wiring only.
- `src/cli.rs` may be larger when it is mostly declarative Clap definitions.

## Manual Workflow

Use a test-first loop:

1. Run the relevant test/check.
2. Review the output.
3. Fix the issue or continue only after understanding the result.

Do not guess past failing checks.

## Release Honesty

- The validated limiter path is `zelynic strict`.
- The `zelynic run` path is experimental planning/preflight groundwork.
- Do not overclaim live `systemd-run` behavior.
- `zelynic run --execute` must remain non-mutating until live execution is
  deliberately implemented and validated.

## Test Discipline

Tests must verify **behavior**, never **identity**. A test assertion that
a constant value matches itself (tautology) provides zero information and
breaks the suite on every unrelated change.

### Forbidden: tautological version assertions

```rust
// FORBIDDEN — Cargo.toml always contains its own version field.
// Always true, zero information.
assert!(include_str!("../Cargo.toml").contains("version = \"3.1.1\""));
```

### Forbidden: test-on-test meta-pattern

Tests must not assert that **other test files** contain a particular
literal string. Every version bump would force manual edits across
multiple test files just to satisfy one meta-test.

```rust
// FORBIDDEN — tests that another test file contains a literal version.
let p14 = include_str!("ledger_p14_tests.rs");
assert!(p14.contains("3.1.0"), "p14 tests must assert 3.1.0");
```

### Allowed: dynamic version assertions

```rust
// ALLOWED — env!() injects the compile-time package version from
// Cargo.toml [package] version. Single source of truth.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
assert!(include_str!("../Cargo.toml")
    .contains(&format!("version = \"{}\"", CURRENT_VERSION)));
```

### Allowed: historical CHANGELOG assertions

Asserting that a past release has an entry in CHANGELOG is legitimate —
those entries are immutable historical record and remain valid forever.

```rust
// ALLOWED — verifies CHANGELOG has an entry for a historical release.
let changelog = include_str!("../CHANGELOG.md");
assert!(changelog.contains("## v3.0.1"));
```

### Enforcement

`scripts/check-version-anti-patterns.sh` (run by `build.sh check-all`)
scans `src/**/*.rs` for forbidden patterns and fails the build if any
are detected. The guard catches:

- `contains("version = \"X.Y.Z\"")` and `contains(r#"version = "X.Y.Z""#)`
- Test-on-test meta-pattern: `include_str!()` another test file followed
  by `contains("X.Y.Z")` semver literal

If a future test genuinely needs the current package version, use
`env!("CARGO_PKG_VERSION")` — never hardcode the literal string. The
current package version is already verified by
`tests/integration_test.rs::test_version` (which uses the `--version` CLI
flag), so per-module version assertions are redundant anyway.

