# AGENTS.md

Guidance for AI coding agents working on Heim.

## Current State

This repository is currently a scaffold. The product spec is not finalized.

Avoid implementing product logic until the relevant behavior has been accepted.
Scaffolding, build wiring, formatting, CI, and empty crate boundaries are fine.

After any significant project structure or workflow change, verify this file
still reflects the current repository state and update it if needed.

## Language

Write code, comments, commit messages, PR text, and technical documentation in
US English.

## Platform Support

Heim targets Linux and macOS first. Preserve Windows compatibility where it is
reasonable and does not compromise the Linux and macOS experience.

## Development Process

When the requested work could encode product behavior, first identify the
specific behavior or boundary being changed and wait for user validation before
implementation. Keep changes scoped to the approved request.

For scaffolding and build wiring, prefer minimal placeholders over speculative
implementation.

## Git And PRs

Do not commit or push unless the user explicitly asks for it.

When the user asks for a commit, keep the commit scope tight and use a short
Conventional Commit subject:

```text
<type>[optional scope]: <description>
```

Common types:

- `chore:`
- `fix:`
- `feat:`
- `docs:`
- `refactor:`
- `test:`
- `build:`
- `ci:`
- `perf:`
- `style:`
- `revert:`

Breaking changes use `!` after the type/scope or a `BREAKING CHANGE:` footer.

Pull requests merge to `main` with squash and merge. The PR title becomes the
squashed commit subject, so PR titles must also be valid Conventional Commits.
Fill in the repository PR template and delete sections that do not apply.

When preparing a PR, include:

- summary of changes
- validation performed
- notes about intentionally deferred behavior or unresolved spec questions

Maintain `CHANGELOG.md` using Keep a Changelog 1.1.0:

- Keep an `Unreleased` section at the top.
- Write entries for humans, not as raw commit logs.
- Use the standard categories when relevant: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, and `Security`.

GitHub Actions should use least-privilege permissions. Prefer pinning third
party actions to commit SHAs once the workflow is finalized.

## Validation

Before running local checks on a fresh machine, install the required Rust
components:

```bash
make setup
```

Before handing off Rust changes, run:

```bash
make ci
```

This expands to format, check, clippy, and tests for the whole workspace.
