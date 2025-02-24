import re
import time
from utils import create_driver, get_payloads_from_file, has_query, load_db_patterns
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)


def test_by_query(driver, target_url, payload_list, attack_type):
    """
    Tests for vulnerabilities by injecting payloads into the URL query string
    if the target URL contains a query string.

    Parameters:
        driver (webdriver): Selenium WebDriver instance used to interact with the web page.
        target_url (str): The URL of the target application to test.
        payload_list (list): A list of payloads to inject into the target URL.
        attack_type (str): The type of attack being performed (e.g., 'XSS').
    """

    for payload in payload_list:
        # Inject the payload into the URL query string
        modified_url = f"{target_url}{payload}"
        driver.get(modified_url)

        time.sleep(2)  # Wait for the page to load completely

        # Check if an alert appeared after modifying the URL
        handle_response(driver, modified_url, payload, attack_type)


def handle_response(driver, target_url, payload, attack_type):
    """
    Handles the response from the target web page after submitting a payload.

    Parameters:
        driver (webdriver): Selenium WebDriver instance used to interact with the web page.
        target_url (str): The URL of the target application.
        payload (str): The payload that was injected into the target URL or input field.
        attack_type (str): The type of attack being performed (e.g., 'XSS', 'SQLI').
    """

    # Build message for logging
    message = f"URL: {target_url} | Payload: {payload}"

    if attack_type == "XSS":
        # Check for XSS vulnerability by detecting alert popups
        try:
            alert = driver.switch_to.alert
            print(Fore.GREEN + f"[+] Possible XSS found: {message}")
            alert.accept()
        except Exception:
            print(Fore.RED + f"[-] No XSS found: {message}")

    elif attack_type == "SQLI":
        # Detect SQL Injection vulnerabilities by looking for error patterns
        db_error_patterns = load_db_patterns()
        page_source = driver.page_source

        db_found = next((db_type for db_type, pattern in db_error_patterns.items()
                         if re.search(pattern, page_source, re.IGNORECASE)), None)

        if db_found:
            print(Fore.GREEN + f"[+] Possible SQL Injection found: {message} | Database: {db_found}")
        else:
            print(Fore.RED + f"[-] No SQL Injection found: {message}")

def perform_scan(attack_type, target_url, payload_list, headers=None):
    """
    Executes the vulnerability scanner based on the provided attack type (e.g., XSS).

    Parameters:
        attack_type (str): The type of attack to perform (e.g., 'XSS').
        target_url (str): The URL of the target application to test.
        payload_list (str): The file path or list of payloads to use for testing.
        headers (dict): A dictionary of HTTP headers to use for each request.
    """

    # Check if the URL contains a query string
    has_query(target_url)

    # Load payloads from the given file path
    payload_list = get_payloads_from_file(payload_list)

    # Create a new browser driver for testing
    driver = create_driver(headers)

    # Perform testing by injecting payloads into the URL query string
    print(Fore.CYAN + "[*] Starting scan...")
    test_by_query(driver, target_url, payload_list, attack_type)

    # Close the WebDriver after the scan
    driver.quit()
    print(Fore.CYAN + "[*] Scan completed.")
