"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import utils


def xss_menu():
    """Displays the XSS scanning menu and handles user input."""
    print("\n" + "#" * 50)
    print("             XSS VULNERABILITY SCANNER")
    print("#" * 50)

    while True:
        target_url = input("Enter target host URL (e.g., https://example.com/page): ").strip()
        if utils.check_url_alive(target_url):
            break

    payload_list = input("Enter payload-list path (leave empty for default): ").strip()
    if not payload_list:
        payload_list = "PayloadLists/xss.txt"
        print(f"No wordlist provided. Using default: {payload_list}")

    perform_xss_scan(target_url, payload_list)


def perform_xss_scan(url, payload_list):
    """Performs XSS scan on the given URL using the specified payload list."""
    payloads = utils.get_payloads_from_file(payload_list)
    if not payloads:
        print("No payloads loaded.")
        return

    inputs = utils.get_inputs(url)
    if not inputs:
        print("No input fields found.")
        return

    print(f"Found inputs: {inputs}")
    utils.test_inputs(url, inputs, payloads)
