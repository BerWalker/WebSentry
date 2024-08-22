"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import re
import logging
import requests
from utils import get_payloads_from_file, get_inputs, has_query

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_sql_injection_scan(url, payload_list):
    """Performs SQL Injection scan on the given URL using the specified payload list."""
    payloads = get_payloads_from_file(payload_list)
    if not payloads:
        logging.warning("No payloads loaded.")
        return

    if not has_query(url):
        inputs = get_inputs(url)
        if not inputs:
            logging.warning("No input fields found.")
            return

        logging.info(f"Found inputs: {inputs}")
        scan_sql_inputs(url, inputs, payloads)
    else:
        scan_sql_query(url, payloads)


def scan_sql_inputs(url, inputs, payloads):
    """Scan for SQL Injection by sending payloads to input fields."""
    for payload in payloads:
        for input_info in inputs:
            data = {input_info['name']: payload}
            try:
                response = requests.get(url, params=data, timeout=10)
                handle_response(response, input_info['name'], payload)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing inputs: {e}")


def scan_sql_query(url, payloads):
    """Scan the URL by appending payloads directly."""
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=10)
            handle_response(response, url, payload)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error testing inputs: {e}")


def handle_response(response, identifier, payload):
    """Handle HTTP response and detect SQL Injection."""
    if response.status_code == 200:
        if detect_sql_injection(response.text):
            logging.info(f"Possible SQL Injection vulnerability detected "
                         f"(identifier: {identifier}): Payload: {payload}")
        else:
            logging.info(f"Nothing found (identifier: {identifier}): Payload: {payload}")
    elif response.status_code == 500:
        logging.info(f"Server error (500) for payload: {payload}")
    else:
        logging.warning(f"Non-200 response code: {response.status_code} for payload: {payload}")


def detect_sql_injection(response_text):
    """Detects signs of SQL Injection in the response text."""
    file_path = 'PayloadLists/sql_errors.txt'

    try:
        with open('PayloadLists/sql_errors.txt', 'r', encoding='utf-8') as file:
            patterns = file.read().splitlines()
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return False
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return False

    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    for pattern in compiled_patterns:
        if pattern.search(response_text):
            return True

    return False
