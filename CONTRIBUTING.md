# Contributing to NetScan

Thanks for taking the time to improve NetScan. This project is deliberately
small: a typed Python engine with a Rich console front-end and no clever
dependencies. Contributions that keep it that way are very welcome.

## Before you start

- **Only test systems you own or are authorised to test.** Engine tests must
  bind loopback servers inside the test process and must never contact a third
  party. See [docs/AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md).
- For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a
  public issue.
- For a large change, open an issue first so we can agree on the shape before
  you write code.

## Development setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e ".[dev]"
pre-commit install
```

The package targets Python 3.10+, so avoid syntax and standard-library APIs
that only exist in newer versions. `tomllib` is imported through a `tomli`
fallback for 3.10.

## Checks

Run the same checks CI runs before opening a pull request:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy netscan
python -m unittest discover -s tests -t . -v
python -m coverage run -m unittest discover -s tests -t . && python -m coverage report
python -m pip_audit -r requirements.txt
```

`pre-commit run --all-files` runs the formatting and lint hooks for you.

## What we look for

- **Behaviour first.** New features need tests. Bug fixes need a test that
  fails before the fix and passes after it.
- **No regressions in the console UI.** Check narrow and wide terminals, and
  both colour and `--no-color` output. Rich style names must exist in
  `netscan/ui.py`'s theme.
- **Machine-readable output stays stable.** JSON field names and CSV headers
  are part of the interface. Add fields; do not silently rename them.
- **Reports stay self-contained.** HTML output must not gain scripts, external
  fonts or network requests, and every interpolated value must be escaped.
- **Safety gates stay intact.** The load tester must remain single-origin, keep
  its hard caps and authorization checks, and must not add spoofing, reflection
  or amplification.
- **Explicit flags beat configuration.** `netscan.toml` is a convenience, never
  a lock-in.
- **Style matches the surroundings.** Small functions, `from __future__ import
  annotations`, type hints on public surfaces, and comments that explain *why*
  rather than *what*.

## Commit messages

Short imperative subject lines are preferred:

```
Add per-host pacing to the scan engine
Fix HTML escaping in service banners
```

Group related changes into one commit where practical.

## Adding a new option

1. Add the flag to the relevant parser (`cli.py` or `stress_cli.py`).
2. Add it to the config schema and `apply_*_config` in `netscan/config.py` if it
   should be configurable.
3. Thread it through the value object and engine.
4. Update the README table and examples.
5. Add tests for validation, behaviour and configuration precedence.

## Releasing

1. Bump `VERSION` in `netscan/constants.py` and `version` in `pyproject.toml`.
2. Update the README where defaults or output change.
3. Run the full check suite.
4. Tag the release and publish the built artefact.
