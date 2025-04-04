# Security Vulnerability Scanner

A command-line tool for scanning code repositories and detecting potential security vulnerabilities based on OWASP guidelines.

## Installation

```bash
git clone https://github.com/yourusername/security-owasp
cd security-owasp/script-scanner
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python security_scanner.py --path /path/to/code
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--path` | `-p` | Path to directory or file to scan (default: current directory) |
| `--recursive` | `-r` | Scan directories recursively |
| `--verbose` | `-v` | Show detailed output |
| `--output` | `-o` | Output file for results |
| `--exclude` | `-e` | Directories to exclude (e.g., node_modules, vendor) |
| `--all` | | Run all available detectors |

## Available Detectors

You can select specific detectors to run:

| Detector | Option | Description |
|----------|--------|-------------|
| Mass Assignment | `--mass-assignment` | Detects mass assignment vulnerabilities in PHP code |
| Sensitive Data Cache | `--sensitive-cache` | Detects sensitive data stored in cache |
| Plaintext OTP | `--plaintext-otp` | Detects plaintext OTP storage in code |

If no specific detectors are selected, all detectors will run by default.

## Examples

Scan a specific project recursively:
```bash
python security_scanner.py --path /path/to/project --recursive
```

Scan with specific detectors only:
```bash
python security_scanner.py --path /path/to/project --mass-assignment --plaintext-otp
```

Exclude certain directories and save results to a file:
```bash
python security_scanner.py --path /path/to/project --recursive --exclude node_modules vendor --output results.txt
```

Show detailed output:
```bash
python security_scanner.py --path /path/to/project --verbose
```

## Output Format

When issues are found, the output will include:
- The detector that found the issue
- The file and line number where the issue was found
- A description of the issue
- The relevant code snippet (if available)

Example output:
```
mass-assignment: /path/to/file.php:25
  Mass assignment vulnerability detected in model definition
  Code: $model->update($request->all());

plaintext-otp: /path/to/auth.php:42
  OTP code stored in plaintext
  Code: $user->otp = $generated_code;
```
