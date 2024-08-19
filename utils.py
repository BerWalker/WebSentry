"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import requests
from bs4 import BeautifulSoup


def check_url_alive(url):
    """Checks if the given URL is reachable."""
    try:
        response = requests.head(url, timeout=5)
        return response.status_code < 400
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL: {e}")
        return False


def get_payloads_from_file(file_path):
    """Reads payloads from a file and returns them as a list."""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            payloads = f.read().splitlines()
        return payloads
    except IOError as e:
        print(f"Error reading payload file: {e}")
        return []


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
