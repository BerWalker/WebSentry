"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""

import time
import xsser


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
        xsser.xss_menu()
    elif choice == "2":
        print("\nSQL Injection selected.")
        # Placeholder for SQL Injection functionality
        pass
    elif choice == "3":
        print("Exiting...")
        return False
    else:
        print("Invalid choice. Please select a valid option.")
        time.sleep(2)
        print('\n' * 3)
    return True


if __name__ == '__main__':
    while True:
        print_menu()
        user_choice = input("Enter your choice: ").strip()
        if not handle_choice(user_choice):
            break
