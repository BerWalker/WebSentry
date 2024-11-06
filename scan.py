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
import sys
import requests
from utils import get_payloads_from_file, get_inputs, has_query
from datetime import datetime, timezone

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_scan(url, payload_list, attack_type, headers=None):
    """Performs SQL Injection or XSS scan on the given URL using the specified payload list."""
    payloads = get_payloads_from_file(payload_list)
    results = []

    if not has_query(url):
        inputs = get_inputs(url)
        results.extend(scan_inputs(url, inputs, payloads, attack_type, headers))
    else:
        results.extend(scan_query(url, payloads, attack_type, headers))

    return results


def scan_inputs(url, inputs, payloads, attack_type, headers):
    """Scan for SQL Injection or XSS by sending payloads to input fields."""
    results = []
    for payload in payloads:
        for input_info in inputs:
            data = {input_info['name']: payload}
            try:
                response = requests.get(url, params=data, headers=headers, timeout=10)
                result = handle_response(response, input_info['name'], payload, attack_type)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing inputs: {e}")
                sys.exit(1)
            if result:
                results.append(result)
    return results


def scan_query(url, payloads, attack_type, headers):
    """Scan the URL by appending payloads directly."""
    results = []
    for payload in payloads:
        try:
            response = requests.get(url + payload, headers=headers, timeout=10)
            result = handle_response(response, url, payload, attack_type)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error testing query: {e}")
            sys.exit(1)
        if result:
            results.append(result)
    return results


def handle_response(response, identifier, payload, attack_type):
    """Handle HTTP response and detect SQL Injection or XSS."""

    # Ensure that response has expected attributes
    if not hasattr(response, 'status_code') or not hasattr(response, 'text'):
        logging.error("Response object is missing required attributes.")
        sys.exit(1)

    # Handle different status codes
    match response.status_code:
        case 200:
            match attack_type:
                case 'SQLI':
                    if detect_sql_injection(response.text):
                        logging.info(f"Possible SQL Injection vulnerability detected "
                                     f"(identifier: {identifier}): Payload: {payload}")
                        return {
                            "identifier": identifier,
                            "payload": payload,
                            "attack_type": attack_type,
                            "url": response.url,
                            "http_status_code": response.status_code,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    else:
                        logging.info(f"No SQL Injection detected (identifier: {identifier}): Payload: {payload}")

                case 'XSS':
                    if payload in response.text:
                        logging.info(f"Possible XSS vulnerability detected"
                                     f" (identifier: {identifier}): Payload: {payload}")
                        return {
                            "identifier": identifier,
                            "payload": payload,
                            "attack_type": attack_type,
                            "url": response.url,
                            "http_status_code": response.status_code,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }

                    else:
                        logging.info(f"No XSS detected (identifier: {identifier}): Payload: {payload}")
                case _:
                    logging.info(f"Unknown attack type {attack_type}")
                    sys.exit(1)
        case 400:
            logging.error(f"Bad Request (400) for payload: {payload} (identifier: {identifier})")
        case 404:
            logging.error(f"Not Found (404) for payload: {payload} (identifier: {identifier})")
        case 500:
            logging.error(f"Server error (500) for payload: {payload} (identifier: {identifier})")
        case _:
            logging.warning(
                f"Non-200 response code: {response.status_code} for payload: {payload} (identifier: {identifier})")
    return None


def detect_sql_injection(response_text):
    """Detects signs of SQL Injection in the response text."""
    file_path = 'PayloadLists/sql_errors.txt'

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            patterns = file.read().splitlines()
    except FileNotFoundError:
        logging.error(f"Error: The file {file_path} was not found.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    for pattern in compiled_patterns:
        if pattern.search(response_text):
            return True

    return False
