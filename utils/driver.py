"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

from colorama import Fore
from selenium.webdriver.firefox.options import Options
from seleniumwire import webdriver


def create_driver(custom_headers=None):
    try:
        # Set up Firefox options to run in headless mode (no GUI)
        options = Options()
        options.add_argument("--headless")

        # Additional seleniumwire options for request interception
        seleniumwire_options = {}

        # Initialize the Firefox WebDriver with the specified options
        driver = webdriver.Firefox(options=options, seleniumwire_options=seleniumwire_options)

        # If custom headers are provided, set up an interceptor to modify request headers
        if custom_headers:
            def interceptor(request):
                request.headers = custom_headers.copy()  # Replace request headers with custom ones

            driver.request_interceptor = interceptor  # Apply the interceptor to the driver

        return driver  # Return the configured driver
    except Exception as e:
        # Print error in red if WebDriver creation fails
        print(Fore.RED + f"[!] Error creating WebDriver: {e}")
        raise  # Raise the exception for external handling
