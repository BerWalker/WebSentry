from abc import ABC, abstractmethod
from utils.driver import create_driver
from utils.io_utils import get_payloads_from_file
from utils.network import has_query
from colorama import Fore

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