---
name: changelog
description: Write, update, review, or cut releases from a CHANGELOG.md following Keep a Changelog — entry types (Added, Changed, Deprecated, Removed, Fixed, Security), the Unreleased section, ISO dates, and yanked releases. Use whenever the user mentions changelogs, release notes, or documenting what changed in a version. For version numbers, use semver. Not for commit messages or PR descriptions.
metadata:
  author: Aaron
  version: "1.0.0"
---

# Changelog

Follow the repo's existing changelog format first; apply Keep a Changelog only where none exists. A changelog is a curated, human-readable list of notable changes per version — never a dump of the git log.

## Format

Name the file `CHANGELOG.md` (not `HISTORY`, `NEWS`, `RELEASES`).

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Export ignored the `format` query parameter.

## [1.2.0] - 2026-10-31

### Added
- CSV export for reports.

### Deprecated
- `exportXml()` — use `export("xml")` instead; removal planned for 2.0.0.

[Unreleased]: https://github.com/user/repo/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/user/repo/releases/tag/v1.2.0
```

- Latest version first; every released version gets an entry.
- Dates as `YYYY-MM-DD` — unambiguous and sortable; never `10/31/2026` or `Oct 31st`.
- Version headings are link references pointing at the tag or compare view, so sections are linkable.
- State up top whether the project follows Semantic Versioning (pick the number with the semver skill).

## Entry types

| Type | For |
| --- | --- |
| `Added` | New features |
| `Changed` | Changes to existing functionality |
| `Deprecated` | Soon-to-be removed features |
| `Removed` | Now-removed features (promoted from `Deprecated`) |
| `Fixed` | Bug fixes |
| `Security` | Vulnerability fixes |

One type per entry. When torn between `Changed` and `Fixed`: unintended behavior corrected is `Fixed`; intended behavior altered is `Changed`.

## Workflow

- **Adding an entry**: record notable changes under `Unreleased` as they land, not at release time. One bullet per user-visible change; no commit SHAs, no merge-commit noise.
- **Cutting a release**: turn `## [Unreleased]` into `## [<new version>] - <today>`, start a fresh empty `## [Unreleased]` above it, and add the link reference. Pick the version with the semver skill.
- **Reviewing**: check the anti-patterns below first; then that every version has an entry and every date parses as ISO.

## Anti-patterns

- **Commit dumps.** Merge commits, "fix typo", docs-only commits are noise. An entry summarizes the noteworthy difference, often spanning several commits, for humans.
- **Soft-pedaling breakage.** Deprecations, removals, and breaking changes are the most valuable content. If nothing else is recorded, record these — upgrading users must be able to see what will break, remove their usage, then upgrade again.
- **Ambiguous dates.** Regional formats confuse readers; ISO `YYYY-MM-DD` doesn't.
- **Partial updates.** A changelog that misses changes is as dangerous as none — users assume it's the single source of truth. Keep it consistent, or don't keep one.

## Edge cases

- **Yanked releases** stay listed: `## [0.0.5] - 2026-01-13 [YANKED]`. The tag is loud on purpose and bracketed so it parses.
- **GitHub Releases** are not a changelog: non-portable and easy to miss. Keep `CHANGELOG.md` as the source of truth; generate release notes from it.
- **Rewriting is fine** to add a missed release or a forgotten breaking change. Unlike released code, released changelog entries may be corrected.
- No universal standard exists beyond this convention — don't reformat a repo's established changelog wholesale to match it.
