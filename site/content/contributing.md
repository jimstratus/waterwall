# Contributing

Waterwall is a single-operator homelab tool maintained in the open. Contributions, bug reports,
and ideas are welcome — with the understanding that the project's scope stays deliberately
narrow (see the [Threat Model](threat-model.html)).

## Reporting bugs and suggesting features

- **Bugs and feature requests:** open an issue on the
  [issue tracker](https://github.com/jimstratus/waterwall/issues). The repository provides issue
  templates for each.
- For a **bug**, include: your OS/Python version, the exact command, what you expected, what
  happened, and any relevant `journalctl -u waterwall-proxy` output (with secrets redacted).
- For a **feature**, describe the problem first, then your proposed solution and any alternatives.

!!! warning "Never paste real secrets"
    When attaching logs or repro steps, scrub real credentials. Use the example value
    `AKIAIOSFODNN7EXAMPLE` or obvious fakes.

## Development setup

```bash
git clone https://github.com/jimstratus/waterwall.git
cd waterwall
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest          # the suite should pass: 0 failed
```

Tests do not shell out to `openssl` — they build fixtures with the `cryptography` library, so
they run portably on Linux and Windows.

## Conventions

The project uses **bite-sized, test-driven development**:

1. Write a failing test for the behavior.
2. Run it and confirm it fails for the right reason.
3. Write the minimal code to pass.
4. Run it and confirm it passes.
5. Commit — **one logical change per commit**, with a clear `feat(scope): …` / `fix(scope): …` /
   `test(scope): …` message.

- Branch from the default branch with a descriptive name (`feat/…`, `fix/…`, `docs/…`).
- Keep changes focused; large unrelated refactors in the same PR slow review.
- Match the surrounding code's style — `ruff` and `mypy` are in the `[dev]` extra.
- New credential patterns must be tested against a synthetic-secret corpus to avoid false
  positives; never test against real keys.

## Pull requests

Open a PR against the default branch. Describe what changed and why, link any related issue, and
make sure `pytest` passes. Smaller PRs land faster.

## Scope expectations

Waterwall intentionally does **not** try to be a multi-tenant service, a general DLP product, or
tamper-*proof* against a root attacker. Proposals that broaden the threat model beyond a single
trusted operator are likely out of scope — but an issue is still a great place to discuss the
idea.
