# Contributing to LibSignal Rust

Thank you for your interest in contributing to LibSignal Rust! We appreciate your help in making this project better. By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

We welcome contributions of all kinds, including:
- Reporting bugs
- Suggesting new features
- Improving documentation
- Submitting code for bug fixes or new features

### Reporting Bugs

If you find a bug, please check the [issues](https://github.com/DitzDev/libsignal-rust/issues) to see if it has already been reported. If not, open a new issue with a clear and descriptive title. Please include as much detail as possible, such as:
- The version of the library you are using
- The Rust version and operating system
- A clear description of the problem
- Steps to reproduce the bug
- Any relevant code snippets or error messages

### Suggesting Features

We love new ideas! If you have a suggestion for a new feature, please open an issue to discuss it first. This allows us to align on the project's direction and helps prevent duplicate work.

### Submitting Code

Before you start writing code, please check the existing issues or open a new one to discuss your proposed changes. This helps ensure that your work aligns with the project's goals.

Here's a general workflow for submitting a pull request:

1.  **Fork the Repository**: Start by forking the `libsignal-rust` repository to your GitHub account.
2.  **Clone Your Fork**:
    ```bash
    git clone https://github.com/your-username/libsignal-rust.git
    cd libsignal-rust
    ```
3.  **Create a New Branch**: Create a new branch for your feature or bug fix.
    ```bash
    git checkout -b feature/my-new-feature
    # or for a bug fix
    git checkout -b fix/issue-number-description
    ```
4.  **Make Your Changes**: Write your code and make sure to include new tests that cover your changes.
5.  **Run Tests**: Ensure all tests pass before committing.
    ```bash
    cargo test
    ```
6.  **Check Formatting and Lints**: We use `rustfmt` and `clippy` to maintain code quality. Please run them and fix any warnings or errors.
    ```bash
    cargo fmt --all
    cargo clippy --all-targets --all-features
    ```
7.  **Commit Your Changes**: Write a clear and concise commit message.
    ```bash
    git commit -m "feat: Add new feature"
    # or for a bug fix
    git commit -m "fix: Resolve issue with session initialization"
    ```
8.  **Push to Your Fork**:
    ```bash
    git push origin feature/my-new-feature
    ```
9.  **Open a Pull Request**: Go to the original `libsignal-rust` repository and open a new pull request from your branch. Please provide a clear description of your changes and reference the issue it addresses.

### Code Style

- Follow the standard Rust code style enforced by `rustfmt`.
- Write clear, idiomatic Rust.
- Document new public functions, structs, and enums with `///` doc comments.
- Keep function and variable names descriptive.

Thank you for your contribution!