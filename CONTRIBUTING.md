# Contributing

Thanks for helping. Bug reports, false-positive and missed-detection reports, and pull requests are welcome.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest
```

The test suite needs no API keys and makes no paid model calls.

## Ground rules

- Never run package code. Hunter reads archives as data; tests and fixtures must keep it that way.
- Never commit API keys, webhook URLs, `.env` files, or SQLite databases.
- Keep pull requests small and focused, with tests for behavior changes.
- Changes to scoring weights, floors, or cutoffs need before-and-after numbers on the labeled fixtures (`python -m hunter eval`).

## Reporting a detection problem

Open an issue with the ecosystem, package, both versions, the band Hunter gave, and what you expected. Do not paste live malicious payloads into an issue; link the registry page or an advisory instead.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Please read it before you take part.

## Security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability in Hunter itself.
