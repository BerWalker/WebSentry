"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import argparse
import time
from utils import check_url_alive, load_headers_from_file, load_headers
from scan import perform_scan


def parse_arguments():
    """Parses command-line arguments for the vulnerability scanner."""
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - A tool to audit and identify vulnerabilities in web applications. "
                    "Ensure you have authorization to scan the target system.",
        epilog="Example usage:\n"
               "  python3 scan.py -a sqli -u https://example.com -w wordlists/sqli_payloads.txt\n"
               "  python3 scan.py -a xss -u https://example.com/page\n --header-file file.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-a', '--attack',
        choices=['xss', 'sqli'],
        required=True,
        help="Type of attack to perform:\n"
             "  xss   - Cross-Site Scripting scan\n"
             "  sqli  - SQL Injection scan"
    )

    parser.add_argument(
        '-u', '--url',
        required=True,
        help="Target URL to scan. Example format:\n"
             "  https://example.com/page\n"
             "  https://example.com/test?query="
    )

    parser.add_argument(
        '-w', '--wordlist',
        default=None,
        help="Optional path to the payload list file. If not provided, a default wordlist will be used based on "
             "the attack type:\n"
             "  PayloadLists/xss.txt   - for XSS scans\n"
             "  PayloadLists/sqli.txt  - for SQL Injection scans"
    )

    parser.add_argument(
        '--header',
        action='append',
        help="Define custom headers in the format 'Header-Name: value'. Use multiple '--header' flags for multiple headers."
    )

    parser.add_argument(
        '--header-file',
        type=str,
        help="Path to a file with custom headers. Each line should be in 'Header-Name: value' format."
    )

    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_arguments()
        attack_type = args.attack
        target_url = args.url.strip()
        custom_headers = {}

        # Add protocol if missing
        if not (target_url.startswith('http://') or target_url.startswith('https://')):
            target_url = 'https://' + target_url

        # Checking if URL is acessible
        check_url_alive(target_url)

        # Load payload list
        payload_list = args.wordlist if args.wordlist else f'PayloadLists/{attack_type}.txt'

        # Check for custom header-file
        if args.header_file:
            custom_headers = load_headers_from_file(args.header_file)

        # Check for custom single header parameter
        if args.header:
            custom_headers = load_headers(args.header)

        perform_scan(target_url, payload_list, attack_type.upper(), custom_headers)

    except KeyboardInterrupt:
        print("\nExiting...")
        time.sleep(1)