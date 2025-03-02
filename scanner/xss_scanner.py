"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

import time
from datetime import datetime

from colorama import Fore

from scanner.base_scanner import BaseScanner


# Define a scanner class for Cross-Site Scripting (XSS) vulnerabilities
class XSSScanner(BaseScanner):
    def _test_payload(self, payload):
        try:
            # Append the payload to the target URL
            modified_url = f"{self.target_url}{payload}"
            self.driver.get(modified_url)  # Load the modified URL in the driver
            time.sleep(2)  # Wait briefly for the page to load

            # Attempt to detect a JavaScript alert (indicative of XSS)
            alert = self.driver.switch_to.alert
            # If an alert is found, log the success and accept the alert
            print(Fore.GREEN + f"[+] Possible XSS found: {self.target_url} | Payload: {payload}")
            alert.accept()
            return {
                "URL": self.target_url,
                "Payload": payload,
                "attack_type": "XSS",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception:
            # If no alert is triggered or an error occurs, log the failure and return None
            print(Fore.RED + f"[-] No XSS found: {modified_url} | Payload: {payload}")
            return None
