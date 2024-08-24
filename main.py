"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import time
from utils import check_url_alive
from scan import perform_scan


def print_menu():
    """Prints the main menu for the vulnerability scanner."""
    print("\n" + "#" * 50)
    print("            WEB VULNERABILITY SCANNER")
    print("#" * 50)
    print("Select the desired attack:")
    print("1. Cross-Site Scripting (XSS)")
    print("2. SQL Injection")
    print("3. Exit")


def handle_choice(choice):
    """Handles the user's menu choice."""
    match choice:
        case "1":
            print("\nCross-Site Scripting (XSS) selected.")
            vulnerability_scanner_menu("xss")
        case "2":
            print("\nSQL Injection selected.")
            vulnerability_scanner_menu("sqlinjection")
        case "3":
            print("Exiting...")
            time.sleep(1)
            return False
        case _:
            print("Invalid choice. Please select a valid option.")
            time.sleep(2)
            print('\n' * 3)
    return True


def vulnerability_scanner_menu(scanner_type):
    """ Displays a vulnerability scanning menu and handles user input based on the type of scan. """
    print("\n" + "#" * 50)
    print(f"          {scanner_type.upper()} VULNERABILITY SCANNER")
    print("#" * 50)

    while True:
        target_url = input("Enter target host URL (e.g., https://example.com/page or"
                           " https://example.com/test?query=): ").strip()
        if not (target_url.startswith('http://') or target_url.startswith('https://')):
            target_url = 'https://' + target_url
        if check_url_alive(target_url):
            break

    payload_list = input("Enter payload-list path (leave empty for default): ").strip()
    if not payload_list:
        payload_list = f'PayloadLists/{scanner_type}.txt'
    print(f"No wordlist provided. Using default: {payload_list}")

    perform_scan(target_url, payload_list, scanner_type.upper())


if __name__ == '__main__':
    try:
        while True:
            print_menu()
            user_choice = input("Enter your choice: ").strip()
            if not handle_choice(user_choice):
                break
    except KeyboardInterrupt:
        print("\nExiting...")
        time.sleep(1)
        pass
