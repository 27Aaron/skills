# Skills

This repository contains local assistant skills. The main maintained skill is `butian`, a local security audit workflow for code repositories.

## Butian

`butian` scans a project directory and produces local security reports for dependency vulnerabilities, outdated dependencies, hardcoded secrets, tracked sensitive files, `.gitignore` coverage, GitHub Actions, dependency governance, and IaC/container configuration signals.

The default workflow is report-first:

```bash
python3 butian/scripts/run_audit.py /path/to/project
```

The scan writes runtime JSON under the target project's `.butian/<run>/assets/` directory and human-readable reports under:

```text
docs/butian/<date>/security-report.html
docs/butian/<date>/security-report.md
```

Final rescans use:

```text
docs/butian/<date>/security-report-final.html
docs/butian/<date>/security-report-final.md
```

Reports are saved locally and are not opened automatically. The terminal summary prints only the HTML and Markdown report paths.

## Safety Boundaries

Project scans are local and conservative. They do not scan operating-system packages, global npm/pnpm installs, system Python, system services, databases, logs, or remote servers. The scan phase does not modify business source files or dependencies; it only prepares `.butian/`, report files, cache files, logs, and ignore rules for generated artifacts.

Dependency repair is separate from scanning. `fix.py` prints a plan by default and only changes files or runs package-manager commands when called with `--yes`.

## Documentation

- `butian/SKILL.md`: assistant-facing workflow entry.
- `butian/references/project-scan.md`: project scan contract, report rules, and repair interaction rules.
- `docs/butian/index.md`: technical documentation index.
- `docs/butian/testing-matrix.md`: test coverage matrix.

## Verification

Recommended local checks:

```bash
python3 -m unittest discover tests
python3 -m py_compile butian/scripts/*.py
node --check butian/templates/report.js
git diff --check
```
