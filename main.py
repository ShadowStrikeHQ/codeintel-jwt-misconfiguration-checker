#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
import jwt  # PyJWT library

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the JWT Misconfiguration Checker.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Scans code for common JWT misconfigurations.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        help="Path to the file or directory to scan."
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (debug logging)."
    )

    parser.add_argument(
        "--check-secrets",
        action="store_true",
        help="Enable checks for hardcoded secrets."
    )

    parser.add_argument(
        "--output",
        help="Path to save results to a file."
    )

    return parser


def check_file(filepath, check_secrets):
    """
    Scans a single file for JWT misconfigurations.

    Args:
        filepath (str): The path to the file to scan.
        check_secrets (bool): Enable checks for hardcoded secrets.

    Returns:
        list: A list of detected misconfigurations.
    """
    misconfigurations = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

            # Check for 'alg: none'
            if re.search(r"alg *: *['\"]none['\"]", content, re.IGNORECASE):
                misconfigurations.append(f"Insecure 'alg: none' found in: {filepath}")

            # Check for HS256 with short/predictable secrets
            if check_secrets:
                secret_matches = re.findall(r"(secret|key) *: *['\"]([^'\"]*)['\"]", content, re.IGNORECASE)
                for match in secret_matches:
                    secret_name, secret_value = match

                    # Heuristic for weak secrets (very short, predictable patterns)
                    if len(secret_value) < 16:
                        misconfigurations.append(f"Potentially weak secret '{secret_name}' with value '{secret_value}' found in: {filepath}")
                    elif secret_value.lower() in ['secret', 'password', '123456', 'admin', 'test']:
                        misconfigurations.append(f"Potentially weak secret '{secret_name}' with value '{secret_value}' found in: {filepath}")


            # Check for missing expiration checks (e.g., not verifying exp claim)
            if not re.search(r"exp|expiration", content, re.IGNORECASE):
                misconfigurations.append(f"Missing expiration claim handling detected in: {filepath}. Review JWT validation logic.")

            # Look for use of insecure or deprecated libraries and functions
            # Example: Suggesting the use of `jwt.decode` with proper algorithms verification.

            if re.search(r"jwt\.encode\(.*\balgorithm='HS256'", content, re.IGNORECASE):
                misconfigurations.append(f"HS256 encoding found. Recommend considering stronger algorithms in: {filepath}")

            if re.search(r"jwt\.decode\(.*\bverify=False", content, re.IGNORECASE):
                 misconfigurations.append(f"Insecure verification disabled. Verify is set to false, this is unsafe. File: {filepath}")

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return []  # Return empty list if file not found
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")
        return []

    return misconfigurations

def scan_directory(directory, check_secrets):
    """
    Scans a directory recursively for JWT misconfigurations.

    Args:
        directory (str): The path to the directory to scan.
        check_secrets (bool): Enable checks for hardcoded secrets.

    Returns:
        list: A list of detected misconfigurations.
    """
    misconfigurations = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".py", ".js", ".java", ".go")):  # Example file extensions
                filepath = os.path.join(root, file)
                misconfigurations.extend(check_file(filepath, check_secrets))
    return misconfigurations

def main():
    """
    Main function to drive the JWT Misconfiguration Checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    target = args.target
    check_secrets = args.check_secrets

    if os.path.isfile(target):
        misconfigurations = check_file(target, check_secrets)
    elif os.path.isdir(target):
        misconfigurations = scan_directory(target, check_secrets)
    else:
        print(f"Error: Target '{target}' is not a valid file or directory.")
        sys.exit(1)

    if misconfigurations:
        print("JWT Misconfigurations Found:")
        for misconfiguration in misconfigurations:
            print(misconfiguration)

        if args.output:
            try:
                with open(args.output, "w") as outfile:
                    for misconfiguration in misconfigurations:
                        outfile.write(misconfiguration + "\n")
                print(f"Results saved to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")

        sys.exit(1)  # Indicate that vulnerabilities were found
    else:
        print("No JWT misconfigurations found.")
        sys.exit(0)  # Indicate successful scan, no issues found


if __name__ == "__main__":
    main()