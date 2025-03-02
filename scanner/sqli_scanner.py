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
import time
from datetime import datetime

from colorama import Fore

from scanner.base_scanner import BaseScanner
from utils.io_utils import load_db_patterns


# Define a scanner class for SQL Injection vulnerabilities
class SQLiScanner(BaseScanner):
    def __init__(self, target_url, payload_file, headers=None):
        # Initialize the parent BaseScanner class
        super().__init__(target_url, payload_file, headers)
        self.db_patterns = load_db_patterns()  # Load database-specific error patterns

    def _test_payload(self, payload):
        try:
            # Append the payload to the target URL
            modified_url = f"{self.target_url}{payload}"
            self.driver.get(modified_url)  # Load the modified URL in the driver
            time.sleep(2)  # Wait briefly for the page to load
            page_source = self.driver.page_source  # Get the HTML content of the page

            # Check if any database error patterns match the page source
            db_found = next((db_type for db_type, pattern in self.db_patterns.items()
                             if re.search(pattern, page_source, re.IGNORECASE)), None)
            if db_found:
                # If a match is found, log the success and return a result dictionary
                print(Fore.GREEN + f"[+] Possible SQLi found: {self.target_url} | Payload: {payload} | DB: {db_found}")
                return {
                    "URL": self.target_url,
                    "Payload": payload,
                    "attack_type": "SQLI",
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            # If no match, log the failure and return None
            print(Fore.RED + f"[-] No SQLi found: {modified_url} | Payload: {payload}")
            return None
        except Exception as e:
            # Handle any errors during the test (e.g., network issues) and log them
            print(Fore.RED + f"[!] Error: {e}")
            return None
