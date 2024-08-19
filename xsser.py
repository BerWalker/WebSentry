"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import utils
import requests
from bs4 import BeautifulSoup


def xss_menu():
    """Displays the XSS scanning menu and handles user input."""
    print("\n" + "#" * 50)
    print("             XSS VULNERABILITY SCANNER")
    print("#" * 50)

    target_url = input("Enter target host URL (e.g., https://example.com/search?query=): ").strip()
    payload_list = input("Enter payload-list path (leave empty for default): ").strip()
    if not payload_list:
        payload_list = "PayloadLists/xss.txt"
        print(f"No wordlist provided. Using default: {payload_list}")

    if utils.check_url_alive(target_url):
        perform_xss_scan(target_url, payload_list)
    else:
        print("URL not found or not alive")
        exit(1)


def get_inputs(url):
    """Extracts input fields from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        inputs = soup.find_all('input')

        input_details = [{'name': input_element.get('name'), 'type': input_element.get('type', 'text')}
                         for input_element in inputs if input_element.get('name')]
        return input_details
    except requests.exceptions.RequestException as e:
        print(f"Error fetching inputs: {e}")
        return []


def test_inputs(url, inputs, payloads):
    """Tests input fields with payloads for potential vulnerabilities."""
    for payload in payloads:
        for input_info in inputs:
            data = {input_info['name']: payload}
            try:
                response = requests.get(url, params=data)
                if payload in response.text:
                    print(f"Possible vulnerability (input field: {input_info['name']}): Payload: {payload}")
            except requests.exceptions.RequestException as e:
                print(f"Error testing inputs: {e}")


def perform_xss_scan(url, payload_list):
    """Performs XSS scan on the given URL using the specified payload list."""
    payloads = utils.get_payloads_from_file(payload_list)
    if not payloads:
        print("No payloads loaded.")
        return

    inputs = get_inputs(url)
    if not inputs:
        print("No input fields found.")
        return

    print(f"Found inputs: {inputs}")
    test_inputs(url, inputs, payloads)
