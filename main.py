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
from xsser import perform_xss_scan
from sqlinjection import perform_sql_injection_scan


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
    if choice == "1":
        print("\nCross-Site Scripting (XSS) selected.")
        vulnerability_scanner_menu("XSS")
    elif choice == "2":
        print("\nSQL Injection selected.")
        vulnerability_scanner_menu("SQL INJECTION")
        pass
    elif choice == "3":
        print("Exiting...")
        return False
    else:
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
        target_url = input("Enter target host URL (e.g., https://example.com/page): ").strip()
        if check_url_alive(target_url):
            break

    payload_list = input("Enter payload-list path (leave empty for default): ").strip()
    if not payload_list:
        if scanner_type.upper() == "XSS":
            payload_list = 'PayloadLists/xss.txt'
        elif scanner_type.upper() == "SQL INJECTION":
            payload_list = 'PayloadLists/sql.txt'
        print(f"No wordlist provided. Using default: {payload_list}")

    if scanner_type.lower() == "xss":
        perform_xss_scan(target_url, payload_list)
    elif scanner_type.lower() == "sql injection":
        perform_sql_injection_scan(target_url, payload_list)


if __name__ == '__main__':
    while True:
        print_menu()
        user_choice = input("Enter your choice: ").strip()
        if not handle_choice(user_choice):
            break
