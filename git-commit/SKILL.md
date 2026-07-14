---
name: git-commit
description: Create Git commits with Conventional Commit messages by inspecting changes, grouping related files, staging the intended set, and generating a concise message. Use when the user asks to commit changes, create a commit, or generate or rewrite a commit message from repository changes. Only mutate the repository when the user explicitly asks to commit.
---

# Git Commit with Conventional Commits

Analyze the actual changes and create a clear, focused commit using [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/). Follow repository-specific instructions and commitlint rules when present.

## Format

```text
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

## Types

The specification defines `feat`, `fix`, and breaking-change semantics. The other types below are common conventions; repository rules take precedence.

| Type       | Use for                                    |
| ---------- | ------------------------------------------ |
| `feat`     | New feature                                |
| `fix`      | Bug fix                                    |
| `docs`     | Documentation only                         |
| `style`    | Formatting with no logic change            |
| `refactor` | Restructuring without a feature or bug fix |
| `perf`     | Performance improvement                    |
| `test`     | Adding or updating tests                   |
| `build`    | Build system or dependencies               |
| `ci`       | CI configuration or workflows              |
| `chore`    | Maintenance not covered by another type    |
| `revert`   | Reverting changes when tooling supports it  |

## Workflow

### 1. Analyze Changes

```bash
git status --short
git diff --staged
git diff
```

Use the staged diff when it is non-empty. Otherwise, inspect the working-tree diff. Check recent commits or repository configuration when needed to match established language, scopes, and style.

### 2. Stage a Logical Change

Stage files or hunks only for an explicit commit request. Keep one logical change per commit and avoid unrelated files. After staging, inspect `git diff --staged` again and base the message only on that snapshot.

```bash
git add path/to/file
git add -p
```

Never stage secrets or private keys. Inspect credential and environment files carefully before including them.

### 3. Generate the Message

- Choose the type from the change's primary intent.
- Use a scope only when the affected component is clear.
- Write a specific, imperative description such as `add`, `fix`, or `remove`.
- Follow repository language and rules; otherwise match the user's language.
- Keep the header concise. Prefer at most 72 characters when the repository defines no limit.
- Add a body only when the reason or impact is not clear from the header.
- Do not invent issue references, reviewers, co-authors, or sign-offs.

For breaking changes, add `!` before `:` and/or a `BREAKING CHANGE:` footer. When using only `!`, describe what breaks in the header.

```text
feat(api)!: remove the legacy search endpoint

BREAKING CHANGE: use the v2 search endpoint instead
```

### 4. Execute the Commit

Run `git commit` only when the user explicitly asks to commit. Pass the complete message through stdin with `git commit --file=-` or another argv-safe interface; do not interpolate generated text into a shell command.

Allow hooks to run. If a hook fails, fix the cause and retry; do not bypass it automatically. Verify the result with:

```bash
git status --short
git log -1 --oneline
```

Report the commit hash and subject.

## Safety

- Never change Git configuration.
- Never use `--no-verify`, destructive commands, or history rewriting unless explicitly requested.
- Never force-push `main` or `master`; do not force-push another branch unless explicitly requested.
- Never push merely because the user asked to commit.
- For a message-only request, return the message without staging or committing.
