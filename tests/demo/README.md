# Demo Projects

This folder contains small, intentionally imperfect projects for manual report QA.

Run all demo audits:

```bash
python3 tests/demo/run_demo_audits.py
```

Each project writes stable review artifacts to its own `docs/` folder:

- `docs/security-report.md`
- `docs/security-report.html`

Runtime data stays under `.butian/` and is ignored. The demo fixtures use fake generic values such as `demo_password_for_report` and `demo_api_key_for_report`; they are not real credentials.
