"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

from abc import ABC, abstractmethod

from colorama import Fore

from utils.driver import create_driver
from utils.io_utils import get_payloads_from_file
from utils.network import has_query


# Define an abstract base class for all scanners
class BaseScanner(ABC):
    def __init__(self, target_url, payload_file, headers=None):
        # Initialize the scanner with the target URL, payload file, and optional headers
        self.target_url = target_url
        self.payloads = get_payloads_from_file(payload_file)  # Load payloads from the specified file
        self.headers = headers or {}  # Use provided headers or an empty dict if none given
        self.driver = create_driver(self.headers)  # Create a web driver instance with headers
        self.results = []  # Store scan results

    def scan(self):
        # Check if the target URL has query parameters; if not, return empty results
        if not has_query(self.target_url):
            return self.results

        # Start scanning with payloads and display progress
        print(Fore.BLUE + "[*] Testing with payloads...")
        for payload in self.payloads:
            result = self._test_payload(payload)  # Test each payload
            if result:
                self.results.append(result)  # Store successful results
        self.driver.quit()  # Close the web driver after scanning
        return self.results  # Return all findings

    @abstractmethod
    def _test_payload(self, payload):
        # Abstract method to be implemented by subclasses for specific payload testing
        pass
