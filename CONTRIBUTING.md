# Contributing to bifrost-cli

Thanks for your interest in contributing.

## Issues and Feature Requests

We prefer that bugs, questions, and feature requests are submitted as GitHub issues first.

For larger changes or behavior changes, please open an issue before starting implementation so we can align on the direction.

## Development

Build and verify changes using the Makefile targets in this repository:

```bash
make build
make test
make lint
```

If you change dependencies, also run:

```bash
make tidy
```

## Pull Requests

When opening a pull request:

- Describe what changed and why.
- Include tests when the change affects behavior.
- Update documentation when the user-facing behavior changes.
- Make sure the existing checks pass.
- Use conventional commits for commit messages when possible.
- Keep pull requests focused and small enough to review easily.

## Code Style

- Follow the existing style of the repository.
- Prefer simple changes to broad refactors.
- Avoid introducing new dependencies unless they are clearly justified.

## Security

Please do not report security vulnerabilities in public issues or pull requests.

See [SECURITY.md](SECURITY.md) for how to report them privately.
