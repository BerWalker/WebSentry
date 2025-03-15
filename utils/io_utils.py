"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law.
"""

import json
import sys
import xml.etree.ElementTree as Et

from colorama import Fore


def get_payloads_from_file(file_path):
    try:
        # Open and read the file, splitting contents into a list of payloads
        with open(file_path, "r", encoding='utf-8') as f:
            payloads = f.read().splitlines()
        # Print the number of payloads loaded in blue
        print(Fore.BLUE + f"Loaded {len(payloads)} payloads from {file_path}")
        return payloads  # Return the list of payloads
    except Exception as e:
        # Print error in red if file reading fails
        print(Fore.RED + f"[!] Error reading payloads: {e}")
        raise  # Raise the exception


def load_db_patterns(file_path="Patterns/db_patterns.json"):
    try:
        # Load and return JSON data from the specified file
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        # Print error in red if JSON loading fails
        print(Fore.RED + f"[!] Error loading DB patterns: {e}")
        raise  # Raise the exception


def load_headers_from_file(file_path):
    headers = {}
    try:
        # Read headers from the file, expecting "Key: Value" format
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if ':' in line:
                    key, value = line.split(":", 1)  # Split on first occurrence of ":"
                    headers[key.strip()] = value.strip()  # Store stripped key-value pair
        print(f"{Fore.BLUE}Loaded headers from {file_path}")
        # Print each loaded header
        for key, value in headers.items():
            print(f"{Fore.BLUE}Header loaded ({key}: {value})")
    except FileNotFoundError:
        # Exit with error if file is not found
        print(f"{Fore.RED}Error: Header File '{file_path}' not found.")
        sys.exit(1)
    except IOError as e:
        # Exit with error if there's an I/O issue
        print(f"{Fore.RED}Error reading header file '{file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        # Exit with error for unexpected issues
        print(f"{Fore.RED}Unexpected error loading headers: {e}")
        sys.exit(1)
    return headers  # Return the dictionary of headers


def load_headers(headers):
    custom_headers = {}
    # Process a list of header strings in "Key: Value" format
    for header in headers:
        try:
            key, value = header.split(":", 1)  # Split on first ":"
            custom_headers[key.strip()] = value.strip()  # Store stripped key-value pair
            print(f"{Fore.BLUE}Header loaded ({key.strip()}: {value.strip()})")
        except ValueError:
            # Exit with error if format is invalid
            print(f"{Fore.RED}Error: '{header}'. Should be in the format 'Header-Name: value'.")
            sys.exit(1)
        except Exception as e:
            # Exit with error for unexpected issues
            print(f"{Fore.RED}Unexpected error loading header '{header}': {e}")
            sys.exit(1)
    return custom_headers  # Return the dictionary of headers


def export_results(results, filename, format_type):
    try:
        if format_type == "json":
            # Export results as JSON with indentation
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)
        elif format_type == "xml":
            # Create an XML structure for results
            root = Et.Element("ScanResults")
            for result in results:
                item = Et.SubElement(root, "Result")
                for key, value in result.items():
                    Et.SubElement(item, key).text = str(value)  # Add each key-value pair as a subelement
            Et.ElementTree(root).write(filename, encoding='utf-8', xml_declaration=True)
        elif format_type == "plain":
            # Export results as plain text
            with open(filename, "w") as f:
                for result in results:
                    f.write(f"Identifier: {result['URL']}, Payload: {result['Payload']}, "
                            f"Attack Type: {result['attack_type']}, "
                            f"Timestamp: {result['timestamp']}\n")
        # Confirm successful export in green
        print(Fore.GREEN + f"Results exported as {filename} ({format_type}).")
    except Exception as e:
        # Print error in red if export fails
        print(Fore.RED + f"[!] Error exporting results: {e}")
        raise  # Raise the exception
