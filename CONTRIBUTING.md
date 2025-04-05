# Contributing to python-bitcoin-utils

Thank you for considering contributing to the `python-bitcoin-utils` project! Your contributions help improve and expand this library for Bitcoin application development.

## How to Contribute

### 1. Reporting Issues

If you encounter any bugs, unexpected behavior, or have feature requests, please open an issue on the [GitHub Issues](https://github.com/karask/python-bitcoin-utils/issues) page. When reporting a bug, provide the following information:

- A clear description of the issue.
- Steps to reproduce the issue.
- Expected behavior.
- Python version and operating system details.
- Any relevant logs or error messages.

### 2. Feature Requests

If you have an idea for a new feature or improvement, open an issue for discussion before submitting a pull request. This helps ensure alignment with the project's goals and maintainability.

### 3. Code Contributions

We welcome pull requests! To contribute code:

#### Step 1: Fork and Clone the Repository

1. Fork the repository on GitHub.
2. Clone your fork to your local machine:
   ```sh
   git clone https://github.com/your-username/python-bitcoin-utils.git
   cd python-bitcoin-utils
   ```
3. Add the upstream repository to keep your fork updated:
   ```sh
   git remote add upstream https://github.com/karask/python-bitcoin-utils.git
   ```

#### Step 2: Create a Feature Branch

Create a new branch for your changes:

```sh
git checkout -b feature-name
```

#### Step 3: Make Changes and Test

- Follow the project's coding style.
- Ensure your code is well-documented and includes meaningful commit messages.
- Run tests before submitting a pull request:
  ```sh
  pytest tests/
  ```
  Ensure all tests pass and your changes do not introduce regressions.

#### Step 4: Submit a Pull Request

1. Push your changes to your fork's branch:
   ```sh
   git push origin feature-name
   ```
2. Open a pull request from your fork's branch to the `master` branch of the original repository.
3. Provide a detailed description of your changes.
4. Address any requested changes from maintainers.

### 4. Code Style Guidelines

- Follow PEP 8 for Python code styling.
- Use meaningful variable and function names.
- Maintain clear and concise documentation in the code.
- Use 4 spaces for indentation, not tabs.
- Use triple double quotes (""") for docstrings.
- Include type hints for function parameters and return values.
- Maximum line length should be 88 characters.
- Use descriptive variable names that explain the purpose.

### 5. Writing Tests

Ensure new features and bug fixes include test cases. The project uses `pytest` for testing. Run all tests with:

```sh
pytest
```

If you add new features, create corresponding test cases under the `tests/` directory. Ensure your tests cover:
- Normal expected operation
- Edge cases
- Error handling

### 6. Documentation Contributions

Help improve the documentation by submitting corrections, clarifications, or examples. Update the README or other documentation files as needed.

### 7. Release Process

The project follows semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backward-compatible manner
- PATCH version for backward-compatible bug fixes

When contributing changes that would necessitate a version bump, please indicate the suggested version change in your PR description.

## Code of Conduct

Be respectful and follow the open-source community guidelines. Maintain a collaborative and inclusive environment.

---

Thank you for contributing! 🚀