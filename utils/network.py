"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

from urllib.parse import urlparse

import requests
from colorama import Fore


def check_url_alive(url):
    try:
        # Send a HEAD request to check if the URL is reachable
        response = requests.head(url, timeout=5)
        if response.status_code < 400:
            # URL is alive if status code is less than 400
            print(Fore.BLUE + f"URL is reachable: {url} (Status: {response.status_code})")
            return True
        # Ask user to proceed if status code indicates an issue
        print(Fore.YELLOW + f"URL returned {response.status_code}. Proceed? (y/N): ")
        return input().strip().upper() == 'Y'  # Return True if user agrees
    except Exception as e:
        # Print error in red if request fails
        print(Fore.RED + f"[!] Error checking URL: {e}")
        return False


def has_query(url):
    # Parse the URL to check for query parameters
    parsed_url = urlparse(url)
    if not parsed_url.query:
        # If no query params, ask user to proceed
        response = input(Fore.YELLOW + f"No query parameter in {url}. Continue? (y/N): ")
        return response.strip().upper() == 'Y'  # Return True if user agrees
    # Confirm query string presence in blue
    print(Fore.BLUE + "[*] URL contains query string.")
    return True
