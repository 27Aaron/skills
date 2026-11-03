---
name: semver
description: Decide release version numbers per Semantic Versioning 2.0.0 — MAJOR/MINOR/PATCH bumps, 0.y.z initial development, when to ship 1.0.0, pre-release and build metadata, precedence, and deprecation policy. Use whenever the user asks what version a change warrants, whether a change is breaking, or how to version or tag a release. For changelogs and release notes, use changelog. Not for dependency range syntax like `^1.2` or `~1.2.3`.
metadata:
  author: Aaron
  version: "1.0.0"
---

# Semantic Versioning

Apply SemVer 2.0.0 to the project's own releases. If the repo already uses another scheme (CalVer, lockstep, Chrome-style majors), follow it. SemVer presumes a declared public API — in docs or enforced by code; it says nothing useful about a project with none.

## Which number to bump

| Change | Bump |
| --- | --- |
| Backward-incompatible change to the public API | MAJOR (reset minor and patch to 0) |
| Backward-compatible new functionality; any deprecation | MINOR (reset patch to 0) |
| Backward-compatible bug fix — internal change fixing incorrect behavior | PATCH |
| Several kinds at once | The highest applicable |

Judging "breaking": would a reasonable consumer's code stop compiling or observably change behavior? Removing or renaming anything public, tightening input validation, changing defaults, error types, or output formats, and narrowing accepted types are all breaking — even when the old behavior was a bug (but see *judgment calls*).

## 0.y.z and 1.0.0

- `0.y.z` is initial development: anything may change and the public API should not be considered stable. Start at `0.1.0`; breaking changes may ship in a `0.<minor>` bump.
- Ship `1.0.0` once the software is used in production, or users depend on a stable API, or backward compatibility starts dictating design decisions.

## Format rules

- `X.Y.Z` — non-negative integers, no leading zeroes (`1.09.0` is invalid); each part increases numerically (`1.9.0 → 1.10.0 → 1.11.0`).
- A released version is immutable. Fixing a bad release means releasing a new version — never rewriting the tag.
- Pre-release: `-` plus dot-separated identifiers of `[0-9A-Za-z-]` (`1.0.0-alpha`, `1.0.0-alpha.1`, `1.0.0-rc.1`); numeric identifiers get no leading zeroes; ranks below the associated normal version and may not satisfy its compatibility promise.
- Build metadata: `+` plus identifiers (`1.0.0+20130313144700`); ignored entirely when determining precedence.
- `v1.2.3` is not a semantic version. Prefixing with `v` is a common tag convention (`git tag v1.2.3`) — the semver is `1.2.3`.

## Precedence

Compare major, minor, patch numerically; a pre-release ranks below its normal version; then compare pre-release identifiers left to right — numeric ones numerically, others lexically in ASCII sort order; numeric identifiers rank below non-numeric; a longer identifier list ranks above a shorter one when all shared identifiers are equal. Build metadata never matters.

```text
1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta
< 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
```

## Policy

- **Deprecating**: deprecate in a MINOR (update docs, mark the API deprecated), remove in a later MAJOR. There should be at least one minor release carrying the deprecation before the removal ships. Record both in the changelog (changelog skill).
- **Released a breaking change as a MINOR by accident**: release a new minor that restores backward compatibility — never modify the broken release. Document the offending version for users.
- **A "bug fix" that changes behavior people rely on**: strictly a patch, but with a large audience a MAJOR communicates the impact better. Use judgment — the version number is a signal to users first, a correctness exercise second.
- **Updating dependencies without touching the public API**: compatible. PATCH if the update fixed a bug, MINOR if it introduced new functionality.

## Validation

Official regex (numbered groups: 1 = major, 2 = minor, 3 = patch, 4 = prerelease, 5 = build metadata):

```text
^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$
```

When cutting a release, pair with the changelog skill: decide the number here, move its `Unreleased` section into that version there.
