"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import sys
import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse

# Logging Config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def has_query(url):
    parsed_url = urlparse(url)
    return bool(parsed_url.query)


def check_url_alive(url):
    """Checks if the given URL is reachable."""
    try:
        # Send a HEAD request to the URL
        response = requests.head(url, timeout=5)

        # Check if the status code indicates the URL is reachable
        if response.status_code < 400:
            logging.info(f"URL returned status code {response.status_code}: {url}")
            logging.info(f"URL is reachable: {url}")
            return True

        # Handle specific cases for status codes 400
        if response.status_code >= 400:
            if response.status_code == 404:
                logging.error(f"URL returned status code {response.status_code}: {url}")
                sys.exit(1)
            logging.warning(f"URL returned status code {response.status_code}: {url}. Want to continue? (y/N)")
            if input().strip().upper() == 'Y':
                return True
            sys.exit(1)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL: {e}")
        sys.exit(1)

def get_payloads_from_file(file_path):
    """Reads payloads from a file and returns them as a list."""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            payloads = f.read().splitlines()
        logging.info(f"Loaded {len(payloads)} payloads from {file_path}")
        return payloads
    except IOError as e:
        logging.error(f"Error reading payload file: {e}")
        sys.exit(1)

def load_headers_from_file(file_path):
    """Reads headers from a file and returns as a dictionary."""
    headers = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if ':' in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
        logging.info(f"Loaded headers from {file_path}")
        for key, value in headers.items():
            logging.info(f"Header loaded ({key}: {value})")
    except FileNotFoundError:
        logging.error(f"Error: Header File '{file_path}' not found.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Error reading header file '{file_path}': {e}")
        sys.exit(1)
    return headers


def load_headers(headers):
    """Reads custom headers from a string list 'Header-Name: value'."""
    custom_headers = {}

    for header in headers:
        try:
            key, value = header.split(":", 1)
            custom_headers[key.strip()] = value.strip()
            logging.info(f"Header loaded ({key.strip()}: {value.strip()})")
        except ValueError:
            logging.error(f"Erro: '{header}'. Should be in format 'Header-Name: value'.")
            sys.exit(1)

    return custom_headers

def get_inputs(url):
    """Extracts input fields from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        inputs = soup.find_all('input')

        input_details = [{'name': input_element.get('name'), 'type': input_element.get('type', 'text')}
                         for input_element in inputs if input_element.get('name')]
        logging.info(f"Found {len(input_details)} input fields on {url}")
        return input_details
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching inputs: {e}")
        sys.exit(1)