"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import json
import re
import logging
import sys
import requests
from utils import get_payloads_from_file, get_inputs, has_query
from datetime import datetime, timezone

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_scan(url, payload_list, attack_type, headers=None):
    """Performs scanning for SQL Injection, XSS, LFI, or Path Traversal."""
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
    """Handle HTTP response and detect vulnerabilities."""

    # Ensure that response has expected attributes
    if not hasattr(response, 'status_code') or not hasattr(response, 'text'):
        logging.error("Response object is missing required attributes.")
        sys.exit(1)

    # Handle different status codes
    match response.status_code:
        case 200:
            match attack_type:
                case 'SQLI':
                    db_type = detect_sql_injection_and_db_type(response.text)
                    if db_type:
                        logging.info(f"Possible SQL Injection vulnerability detected "
                                     f"(identifier: {identifier}): Payload: {payload}")
                        logging.info(f"Possible Database detected {db_type}")

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

                case 'LFI':
                    lfi = detect_lfi(response.text)
                    if lfi:
                        logging.info(f"Possible LFI vulnerability detected"
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
                        logging.info(f"No LFI detected (identifier: {identifier}): Payload: {payload}")

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


def detect_sql_injection_and_db_type(response_text):
    """Detects SQL Injection and attempts to identify the database type based on error messages."""

    # Loads pattern dictionary
    with open("Patterns/db_patterns.json", 'r', encoding='utf-8') as f:
        db_patterns = json.load(f)

    # Checks for errors and database types
    for db_type, pattern in db_patterns.items():
        if re.search(pattern, response_text, re.IGNORECASE):
            return db_type

    return False

def detect_lfi(response_text):
    """Detects Local File Inclusion (LFI) by searching for specific patterns in response text."""

    # Open the file containing common LFI patterns
    with open("Patterns/lfi_patterns.txt", 'r', encoding='utf-8') as f:
        for pattern in f:
            # If pattern found in the response text, return True
            if pattern.strip() in response_text:
                return True

    return False
