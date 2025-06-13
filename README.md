# codeintel-JWT-Misconfiguration-Checker
Scans code for common JWT (JSON Web Token) misconfigurations, such as weak signature algorithms (e.g., HS256 with insecure secret), missing expiration claims, and usage of 'none' algorithm. Validates JWT libraries configurations. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-jwt-misconfiguration-checker`

## Usage
`./codeintel-jwt-misconfiguration-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--verbose`: No description provided
- `--check-secrets`: Enable checks for hardcoded secrets.
- `--output`: Path to save results to a file.

## License
Copyright (c) ShadowStrikeHQ
