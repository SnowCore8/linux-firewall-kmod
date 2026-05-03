# Contributing to Firewall

Thank you for your interest in contributing to the Firewall project! This document outlines the guidelines for contributing to this kernel-level IP banning module.

## Getting Started

1. Fork the repository and clone your fork
2. Set up your development environment (Linux with kernel headers, gcc, make)
3. Build the project: `make`
4. Run the test suite: `sudo ./tests/run_tests.sh`

## Code Style

- Follow the existing code style and formatting
- Use meaningful variable and function names
- Comment your code in English
- Keep functions focused and modular
- Follow kernel coding standards for C code

## Testing

- All contributions should include appropriate tests
- Run the full test suite before submitting changes
- Add new tests for new functionality
- Ensure all tests pass before submitting a pull request

## Pull Request Process

1. Create a feature branch for your changes
2. Make your changes following the code style
3. Add or update tests as needed
4. Run the full test suite
5. Submit a pull request with a clear description of your changes
6. Link any relevant issues in your pull request description

## Development Guidelines

- Changes to kernel module code should be carefully reviewed for safety
- Memory allocation/deallocation must be properly handled
- RCU and locking mechanisms must be used correctly
- All new features should be documented

## Questions?

If you have questions about contributing, feel free to open an issue for discussion.

Thank you for helping improve Firewall!