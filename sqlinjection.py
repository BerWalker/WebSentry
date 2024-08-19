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
from utils import get_payloads_from_file, get_inputs

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_sql_injection_scan(url, payload_list):
    """Performs SQL Injection scan on the given URL using the specified payload list."""
    payloads = get_payloads_from_file(payload_list)
    if not payloads:
        logging.warning("No payloads loaded.")
        return

    inputs = get_inputs(url)
    if not inputs:
        logging.warning("No input fields found.")
        return

    logging.info(f"Found inputs: {inputs}")

    for input_info in inputs:
        for payload in payloads:
            data = {input_info['name']: payload}
            try:
                response = requests.get(url, params=data, timeout=10)
                if response.status_code == 200:
                    if detect_sql_injection(response.text):
                        logging.info(f"Possible SQL Injection vulnerability detected (input field:"
                                     f" {input_info['name']}): Payload: {payload}")
                    elif response.status_code == 500:
                        logging.info(f"Server error (500) for payload: {payload}")
                    else:
                        logging.info(f"Nothing found (input field: {input_info['name']}): Payload: {payload}")
                else:
                    logging.warning(f"Non-200 response code: {response.status_code} for payload: {payload}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing inputs: {e}")

    exit(1)


def detect_sql_injection(response_text):
    """Detects signs of SQL Injection in the response text."""
    sql_error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning: mysql_",
        r"Unclosed quotation mark after the character string",
        r"org\.postgresql\.util\.PSQLException",
        r"syntax error at or near",
        r"SQLServerException",
        r"ORA-01756",
        r"Unknown column",
        r"database error",
    ]
    for pattern in sql_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False
