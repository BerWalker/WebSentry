"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

import re
import logging
import requests
from utils import get_payloads_from_file, get_inputs, has_query

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_scan(url, payload_list, attack_type):
    """Performs SQL Injection or XSS scan on the given URL using the specified payload list."""
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
        scan_inputs(url, inputs, payloads, attack_type)
    else:
        scan_query(url, payloads, attack_type)


def scan_inputs(url, inputs, payloads, attack_type):
    """Scan for SQL Injection or XSS by sending payloads to input fields."""
    for payload in payloads:
        for input_info in inputs:
            data = {input_info['name']: payload}
            try:
                response = requests.get(url, params=data, timeout=10)
                handle_response(response, input_info['name'], payload, attack_type)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing inputs: {e}")


def scan_query(url, payloads, attack_type):
    """Scan the URL by appending payloads directly."""
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=10)
            handle_response(response, url, payload, attack_type)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error testing query: {e}")


def handle_response(response, identifier, payload, attack_type):
    """Handle HTTP response and detect SQL Injection or XSS."""

    # Ensure that response has expected attributes
    if not hasattr(response, 'status_code') or not hasattr(response, 'text'):
        logging.error("Response object is missing required attributes.")
        return

    # Handle different status codes
    match response.status_code:
        case 200:
            match attack_type:
                case 'SQLINJECTION':
                    if detect_sql_injection(response.text):
                        logging.info(f"Possible SQL Injection vulnerability detected "
                                     f"(identifier: {identifier}): Payload: {payload}")
                    else:
                        logging.info(f"No SQL Injection detected (identifier: {identifier}): Payload: {payload}")

                case 'XSS':
                    if payload in response.text:
                        logging.info(f"Possible XSS vulnerability detected"
                                     f" (identifier: {identifier}): Payload: {payload}")
                    else:
                        logging.info(f"No XSS detected (identifier: {identifier}): Payload: {payload}")

                case _:
                    logging.info(f"Unknown attack type {attack_type}")
        case 400:
            logging.error(f"Bad Request (400) for payload: {payload} (identifier: {identifier})")
        case 404:
            logging.error(f"Not Found (404) for payload: {payload} (identifier: {identifier})")
        case 500:
            logging.error(f"Server error (500) for payload: {payload} (identifier: {identifier})")
        case _:
            logging.warning(
                f"Non-200 response code: {response.status_code} for payload: {payload} (identifier: {identifier})")


def detect_sql_injection(response_text):
    """Detects signs of SQL Injection in the response text."""
    file_path = 'PayloadLists/sql_errors.txt'

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            patterns = file.read().splitlines()
    except FileNotFoundError:
        logging.error(f"Error: The file {file_path} was not found.")
        return False
    except IOError as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False

    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    for pattern in compiled_patterns:
        if pattern.search(response_text):
            return True

    return False
