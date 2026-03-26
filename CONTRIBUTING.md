# Contributing to Model Guard

We love your input! We want to make contributing to Model Guard as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code follows the style guidelines.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/morgaesis/ssh-guard/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/morgaesis/ssh-guard/issues/new).

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Use a Consistent Coding Style

* Use 4 spaces for indentation rather than tabs
* Use `rustfmt` for consistent code formatting
* Run `cargo clippy` and fix any warnings before submitting
* Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

## License

By contributing, you agree that your contributions will be licensed under its MIT License.

## References

This document was adapted from the open-source contribution guidelines template by [Brian A. Danielak](https://gist.github.com/briandk/3d2e8b3ec8daf5a27a62).

## Development Setup

1. Clone the repository
```bash
git clone https://github.com/morgaesis/ssh-guard.git
cd ssh-guard
```

2. Install development dependencies
```bash
cargo install --path .
```

3. Run tests
```bash
cargo test
cargo test --test '*'  # Run integration tests
```

4. Run benchmarks
```bash
cargo bench
```

5. Check formatting and run lints
```bash
cargo fmt --all -- --check
cargo clippy
```

## Code Reviews

The project maintainer(s) review all pull requests. Here's what we look for:

1. Security best practices
2. Code quality and style
3. Test coverage
4. Documentation
5. Git commit history (clear, meaningful messages)

## Security

Please report security vulnerabilities privately to the maintainers. Do not open public issues for security concerns.

## Documentation

- Update relevant documentation when making changes
- Keep API docs up to date
- Add examples for new features
- Follow rustdoc conventions

## Testing

- Write unit tests for new code
- Add integration tests for new features
- Maintain or improve code coverage
- Test edge cases and error conditions

## Commits

- Use meaningful commit messages
- Follow conventional commits format
- Keep commits focused and atomic
- Squash WIP commits before merging

## Pull Request Process

1. Update documentation
2. Run full test suite
3. Update CHANGELOG.md
4. Request review from maintainers
5. Address review feedback
6. Await final approval