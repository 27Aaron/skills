---
name: git-commit
description: Use when the user needs a commit message or title, wants to rewrite an existing commit, prepares to commit staged changes, asks about Conventional Commits format or commitlint rules, or needs help choosing a commit type (feat, fix, docs, refactor, etc). Also applies to squash and merge commit messages, semantic versioning via commits, and breaking change markers.
---

Write commit messages following [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

## Format

```text
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

## Type Selection

| Type       | Purpose                                | SemVer |
| ---------- | -------------------------------------- | ------ |
| `feat`     | New feature                            | MINOR  |
| `fix`      | Bug fix                                | PATCH  |
| `docs`     | Documentation                          | —      |
| `style`    | Formatting (no logic change)           | —      |
| `refactor` | Restructure (no behavior change)       | —      |
| `perf`     | Performance improvement                | —      |
| `test`     | Add / update / delete tests            | —      |
| `build`    | Build system, dependencies             | —      |
| `ci`       | CI workflow                            | —      |
| `chore`    | Maintenance, tooling                   | —      |
| `revert`   | Revert a commit (community convention) | —      |

> `feat` and `fix` are **required** by spec. Others come from Angular convention (@commitlint/config-conventional); custom types allowed with team consensus.

`BREAKING CHANGE` → **MAJOR** (any type). Multiple types fit → pick the **user-visible outcome**.

## Language

Detect the user's request language and match the output:

- **Chinese request** → description in Chinese, tech terms in English. E.g., `feat(parser): 新增 CSV 导出功能`
- **English (default)** → description in English. E.g., `feat(parser): add CSV export feature`
- Type, scope, and footer tokens are always in English.

## Spec Rules (v1.0.0)

### Commit Structure

1. Every commit **MUST** use a type prefix (a noun such as `feat` or `fix`), followed by an **optional** scope, an **optional** `!`, and a **required** colon + space
2. Commits that introduce a new feature **MUST** use type `feat`
3. Commits that fix a bug **MUST** use type `fix`

### Scope

4. A scope **MAY** follow the type. It **MUST** be a noun describing a section of code, enclosed in parentheses. E.g., `fix(parser):`

### Description

5. The description **MUST** immediately follow the colon + space after the type(scope) prefix
6. A longer commit body **MAY** be provided after the description, separated by **one blank line**

### Body

7. Body content is free-form and **MAY** use blank lines to separate paragraphs

### Footer

8. One or more footers **MAY** be provided after the body, separated by one blank line
9. Each footer line **MUST** contain a token followed by `:<space>` or `<space>#` as separator, then the value
10. Footer tokens **MUST** use `-` as hyphen (e.g., `Acked-by`), except `BREAKING CHANGE`
11. Footer values **MAY** contain spaces and newlines; parsing **MUST** continue until the next footer token/separator
12. `BREAKING-CHANGE` (hyphen) and `BREAKING CHANGE` (space) are **synonyms**

### Breaking Changes

13. Breaking changes **MUST** be marked in the commit message, either in the type(scope) prefix or as a footer
14. In a footer: **MUST** contain uppercase `BREAKING CHANGE: <description>`
15. In the prefix: **MUST** be marked with `!` directly before `:`. If `!` is used, the footer **MAY** omit `BREAKING CHANGE:`, but the description **SHOULD** explain what breaks

### Other

16. Types other than `feat` and `fix` **MAY** be used
17. Tool parsing **MUST** be case-insensitive, except `BREAKING CHANGE` which **MUST** be uppercase

## Project Conventions

18. Description **MUST NOT** exceed 72 characters and **MUST NOT** end with a period

## Workflow

1. Check staged changes: `git diff --cached`.
2. **Staged changes exist**: Generate message → execute `git commit -m "<message>"`.
3. **No staged changes**: Inform user to `git add` first, provide the recommended message.

## Heuristics

- Infer type from diff, changed files, and user description before asking questions.
- If type is ambiguous, give 1-2 alternatives with a brief note on the difference.
- If scope is unclear, omit rather than guess.
- If changes mix several concerns, pick the dominant one and suggest a split.

## Rewrite Guidance

- Preserve original intent.
- Remove vague wording (`update stuff`, `fix issue`, `changes`).
- Normalize into valid conventional structure.
- Convert breaking-change notes to `!` or `BREAKING CHANGE:`.

## Examples (English — default)

```text
feat: add CSV export for billing reports
```

```text
fix(auth): prevent refresh token reuse after logout
```

```text
feat(api)!: remove legacy v1 search endpoint
```

```text
feat: support config inheritance

BREAKING CHANGE: rename extendsPath to extends
```

```text
fix: prevent racing of requests

Introduce a request id and a reference to latest request. Dismiss
incoming responses other than from latest request.

Remove timeouts which were used to mitigate the racing issue but are
obsolete now.

Reviewed-by: Z
Refs: #123
```

## Examples (Chinese — when requested in Chinese)

> Structure is identical to English; only the description language changes.

```text
feat: 新增账单报告的 CSV 导出功能
```

```text
fix(auth): 修复登出后 refresh token 仍可复用的问题
```

```text
feat(api)!: 移除旧版 v1 搜索端点
```
