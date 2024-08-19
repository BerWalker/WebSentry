"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import logging
from utils import get_payloads_from_file, get_inputs, test_inputs

# Logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def perform_xss_scan(url, payload_list):
    """Performs XSS scan on the given URL using the specified payload list."""
    payloads = get_payloads_from_file(payload_list)
    if not payloads:
        logging.warning("No payloads loaded.")
        return

    inputs = get_inputs(url)
    if not inputs:
        logging.warning("No input fields found.")
        return

    logging.info(f"Found inputs: {inputs}")
    test_inputs(url, inputs, payloads)

    exit(1)
