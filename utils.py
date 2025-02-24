import sys
import json
import requests
from seleniumwire import webdriver
from selenium.webdriver.firefox.options import Options
from urllib.parse import urlparse
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)


def has_query(url):
    """
    Checks if the given URL contains a query string.

    Parameters:
        url (str): The URL to check.

    Returns:
        bool: True if the URL contains a query string, False otherwise.
    """
    parsed_url = urlparse(url)
    query = bool(parsed_url.query)

    if not query:
        user_response = input(
            f"{Fore.YELLOW}No query parameter found in the URL: {Fore.CYAN}{url}.\n"
            f"Would you like to continue without a query parameter? (y/N): ")

        while user_response.lower() not in ['y', 'n']:
            user_response = input(f"{Fore.RED}Invalid input. Please enter 'y' to continue or 'n' to abort: ")

        if user_response.lower() == 'y':
            print(f"{Fore.BLUE}Continuing without a query parameter...")
            return True
        elif user_response.lower() == 'n':
            print(f"{Fore.RED}Process aborted.")
            exit(0)
    else:
        print(Fore.BLUE + "[*] Target URL contains a query string, testing with payloads...")

    return True


def check_url_alive(url):
    """
    Checks if the given URL is reachable by sending a HEAD request.

    Parameters:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is reachable, False otherwise.

    Raises:
        SystemExit: If an error occurs or the URL is unreachable, the program exits.
    """
    try:
        # Send a HEAD request to the URL
        response = requests.head(url, timeout=5)

        # Check if the status code indicates the URL is reachable
        if response.status_code < 400:
            print(f"{Fore.BLUE}URL returned status code {response.status_code}: {url}")
            print(f"{Fore.BLUE}URL is reachable: {url}")
            return True

        # Handle specific cases for status codes 400 and above
        if response.status_code >= 400:
            if response.status_code == 404:
                print(f"{Fore.RED}URL returned status code {response.status_code}: {url}")
                sys.exit(1)
            print(f"{Fore.YELLOW}URL returned status code {response.status_code}: {url}. Do you want to continue? (y/N)")

            choice = input().strip().upper()
            while choice not in ['Y', 'N']:
                choice = input(f"{Fore.CYAN}Do you want to continue? (y/N): ").strip().upper()

            if choice == 'Y':
                return True

            sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error checking URL: {e}")
        sys.exit(1)


def create_driver(custom_headers=None):
    """
    Creates an instance of the Selenium WebDriver configured to run in headless mode with Firefox.

    Parameters:
        custom_headers (dict, optional): Custom headers to be used for the requests.

    Returns:
        webdriver: The configured Selenium WebDriver instance.
    """
    options = Options()
    options.add_argument("--headless")  # Headless mode

    # Selenium-wire configurations to intercept requests
    seleniumwire_options = {}

    driver = webdriver.Firefox(options=options, seleniumwire_options=seleniumwire_options)

    # If custom headers are provided, apply request interception
    if custom_headers:
        def interceptor(request):
            request.headers = custom_headers.copy()

        driver.request_interceptor = interceptor

    return driver


def get_payloads_from_file(file_path):
    """
    Reads payloads from a file and returns them as a list of strings.

    Parameters:
        file_path (str): The file path to read payloads from.

    Returns:
        list: A list of payload strings read from the file.

    Raises:
        SystemExit: If there is an error reading the file, the program exits.
    """
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            payloads = f.read().splitlines()
        print(f"{Fore.BLUE}Loaded {len(payloads)} payloads from {file_path}")
        return payloads
    except IOError as e:
        print(f"{Fore.RED}Error reading payload file: {e}")
        sys.exit(1)


def load_db_patterns(file_path="Patterns/db_patterns.json"):
    """
    Loads database patterns from a JSON file.

    Parameters:
        file_path (str): The path to the JSON file containing the patterns.

    Returns:
        dict: The database patterns loaded from the file.
    """
    with open(file_path, 'r') as file:
        return json.load(file)


def load_headers_from_file(file_path):
    """
    Reads headers from a file and returns them as a dictionary.

    Parameters:
        file_path (str): The path to the file containing headers.

    Returns:
        dict: A dictionary of headers.

    Raises:
        SystemExit: If there is an error reading the header file, the program exits.
    """
    headers = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if ':' in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
        print(f"{Fore.BLUE}Loaded headers from {file_path}")
        for key, value in headers.items():
            print(f"{Fore.BLUE}Header loaded ({key}: {value})")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Header File '{file_path}' not found.")
        sys.exit(1)
    except IOError as e:
        print(f"{Fore.RED}Error reading header file '{file_path}': {e}")
        sys.exit(1)
    return headers


def load_headers(headers):
    """
    Reads custom headers from a list of strings formatted as 'Header-Name: value'.

    Parameters:
        headers (list): A list of header strings.

    Returns:
        dict: A dictionary of custom headers.

    Raises:
        SystemExit: If there is an error with the header format, the program exits.
    """
    custom_headers = {}

    for header in headers:
        try:
            key, value = header.split(":", 1)
            custom_headers[key.strip()] = value.strip()
            print(f"{Fore.BLUE}Header loaded ({key.strip()}: {value.strip()})")
        except ValueError:
            print(f"{Fore.RED}Error: '{header}'. Should be in the format 'Header-Name: value'.")
            sys.exit(1)

    return custom_headers
