# msadiag

![PHPStan](https://github.com/librarymarket/msadiag/workflows/PHPStan/badge.svg)
[![Maintainability](https://api.codeclimate.com/v1/badges/0c1ab96e14c39992196c/maintainability)](https://codeclimate.com/github/librarymarket/msadiag/maintainability)

The Message Submission Agent Diagnostics tool (msadiag) facilitates testing the
compatibility of third party message submission agents.

This tool implements several tests via SMTP to ensure the target MSA is properly
and securely configured. The following tests are ran with `msadiag validate`:

- The server must not allow authentication via plain-text connection (only with `--strict`).
- The server must support a modern TLS encryption protocol (TLSv1.2 or TLSv1.3).
- The server must use a valid certificate, verifiable using the Mozilla CA bundle.
- The server must support the SMTP AUTH extension.
- The server must support SASL authentication via CRAM-MD5, LOGIN, or PLAIN.
- The server must require authentication to submit messages.
- The server must reject invalid credentials.
- The server must accept valid credentials.
- The server must not require authentication to submit messages after successful authentication.

## Installation

To install this package using Composer, run the following command.

```bash
composer global require librarymarket/msadiag
```

`~/.config/composer/vendor/bin` must be in `PATH` to use the `msadiag` command.

## Usage

Run `msadiag` for a command listing, or `msadiag COMMAND --help` for usage
information about a specific command.

# License

This project is subject to the terms of The MIT License. Please refer to
`LICENSE.txt` for more information, or visit the following URL to get a copy of
the license: https://opensource.org/licenses/MIT
