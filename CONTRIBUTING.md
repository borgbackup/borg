# Contributing to BorgBackup

First of all, thank you for considering contributing to Borg!

This guide provides a brief overview of how to contribute.

For the full, detailed development documentation, please refer to the
[Development Docs](https://borgbackup.readthedocs.io/en/master/development.html).

## How to Contribute

1.  **Discuss Changes:** Before starting major work, please discuss your proposed changes on the [GitHub issue tracker](https://github.com/borgbackup/borg/issues). Smaller changes can also be discussed in the comments of the pull request.
2.  **Branching Model:** Most Pull Requests should be made against the `master` branch. Maintenance branches (e.g., `1.4-maint`) are generally reserved for bug fixes and smaller changes.
3.  **Pull Requests:**
    - Create a feature branch for your changes.
    - Keep changesets clean and focused on a single topic.
    - Reference any related issues in your commit messages.
    - Ensure your PR includes tests and documentation for new features.
    - Proof read your PR yourself, fix typos and other obvious issues.

## Responsible AI Usage

You are welcome to use AI tools, but we require that a human is always "in the loop". 

AI-generated content must not be submitted without active critical review, modification, and integration by the human contributor. We require that the final contribution is a product of human creative control and that AI is only used as a supportive tool to assist the human author.

As the contributor, you are responsible for the entire content of your pull request.

This includes:
- Verifying the correctness and security of any AI-generated code.
- Ensuring that new or modified code is covered by correct tests.
- Proofreading and refining any AI-generated documentation or comments.
- Being able to explain, debug, and maintain the code you submit.

Always be aware of the limitations and the ecological footprint of AI tools and act accordingly:
- Do not just believe what AI tells you, but verify it critically. AI is known to hallucinate, to be over-confident and to always tell you that you are right, even when you are not.
- Do not use AI tools for tasks that can be done more efficiently manually or by simpler tools.
- Learn how to use AI tools efficiently.

## Development Setup

Borg is written in Python with some Cython/C. To set up a development environment:

1.  Create and activate a virtual environment.
2.  Install development dependencies: `pip install -r requirements.d/development.lock.txt`
3.  Install borg in editable mode: `pip install -e .`
4.  Install pre-commit hooks: `pre-commit install`

## Code Style

We use [Black](https://black.readthedocs.io/) for automated code formatting.
- Install black: `pip install -r requirements.d/codestyle.txt`
- Check formatting: `black --check .`
- Apply formatting: `black .`

## Running Tests

We use `tox` and `pytest` for testing.
- Run all tests: `tox`

For more advanced testing options (including Vagrant and Podman), see the full [Development documentation](https://borgbackup.readthedocs.io/en/master/development.html).

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for reporting it.
