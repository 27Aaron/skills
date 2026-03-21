---
name: conventional-commits
description: Write or rewrite Git commit messages using the Conventional Commits 1.0.0 format. Use this skill when the user asks for a commit message, commit title, squash or merge commit text, Conventional Commits help, or to rewrite an existing commit message into a valid conventional format. Prefer a ready-to-use commit title first, then add body or footers only when needed.
---

This skill writes concise, ready-to-use commit messages that follow Conventional Commits 1.0.0.

## Default Output

Use this structure:

```text
<type>[optional scope]: <description>

[optional body]
[optional footer(s)]
```

Return the output in this order:
- Give 1 best commit message first.
- If the classification is ambiguous, give 1-2 alternatives and briefly state the difference.
- If the user provides an existing message, rewrite that message first instead of inventing a new one.

## Core Rules

- Default to an English subject line.
- Keep `type` lowercase.
- Add `scope` only when the module or area is clear from the request, diff, or file paths.
- Keep `description` short, direct, and action-oriented.
- Use a body only when extra context helps explain why or how.
- Use footers only when they add meaningful metadata.
- Do not fold unrelated changes into one commit message. If the work spans unrelated concerns, recommend splitting the commit.

## Type Selection

Prefer these types:
- `feat` for a new feature.
- `fix` for a bug fix.
- `docs` for documentation-only changes.
- `refactor` for internal restructuring without behavior change.
- `perf` for performance improvements.
- `test` for adding or updating tests.
- `chore` for maintenance work that does not fit user-facing behavior changes.
- `ci` for CI workflow or pipeline changes.
- `build` for build system, dependencies, or packaging changes.
- `style` for formatting or style-only changes with no logic change.
- `revert` for reverting an earlier change.

If more than one type seems possible, choose the one that best reflects the user-visible outcome.

## Breaking Changes

Breaking changes may be expressed in either valid form:
- Add `!` before the colon, such as `feat(api)!: drop legacy token format`
- Add a footer, such as `BREAKING CHANGE: remove support for legacy token format`

Use a breaking-change marker only when the change breaks an API, contract, interface, or expected behavior.

## Workflow

When this skill is invoked:

1. Check if there are staged changes in git (`git diff --cached`).
2. **If staged changes exist**: Generate the commit message and directly execute `git commit -m "<message>"`.
3. **If no staged changes**: Inform the user that files need to be added to the staging area first with `git add`, then provide the recommended commit message for later use.

## Working Heuristics

- Infer the type from the diff, changed files, and user description before asking questions.
- If the scope is unclear, omit it instead of guessing.
- If the change mixes several concerns, prefer the dominant change and mention when a split would be cleaner.
- If the user asks in Chinese, you may explain your choice in Chinese, but keep the default commit title in English unless they explicitly want another language.
- Do not assume commitlint, release tooling, or repository-specific type restrictions unless the user states them.

## Rewrite Guidance

When rewriting an existing message:
- Preserve the original intent.
- Remove vague wording like `update stuff`, `fix issue`, or `changes`.
- Normalize it into a valid conventional structure.
- Keep any real breaking-change note and convert it into `!` or `BREAKING CHANGE:` when appropriate.

## Examples

```text
feat: add CSV export for billing reports
```

```text
fix(auth): prevent refresh token reuse after logout
```

```text
docs: clarify local development setup
```

```text
refactor(parser): simplify rule matching flow
```

```text
feat(api)!: remove legacy v1 search endpoint
```

```text
feat: support config inheritance

BREAKING CHANGE: rename extendsPath to extends
```

```text
revert: remove optimistic cache update for profile edits
```
