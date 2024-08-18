"""
Copyright (c) 2024 Bernardo Walker Leichtweis

Licensed under the MIT License. See the LICENSE file for details.

WARNING: This tool is intended for ethical use only. It is designed for auditing and identifying security
vulnerabilities in web applications with explicit authorization from the application owner.

Unauthorized use or use for malicious purposes is strictly prohibited and may be illegal. The author(s) assume no
responsibility or liability for any damage, legal consequences, or other issues arising from the misuse of this tool.
By using this tool, you agree to use it responsibly and within the bounds of the law."""


import time


def print_menu():
    print("\n" + "#"*50)
    print("            WEB VULNERABILITY SCANNER")
    print("#"*50)
    print("Select the desired attack:")
    print("1. Cross-Site Scripting (XSS)")
    print("2. SQL Injection")
    print("3. Exit")


def attack_choice(choice):
    if choice == "1":
        print("\nCross-Site Scripting (XSS) selected.")
        xsser()
    elif choice == "2":
        print("\nSQL Injection selected.")
        # Placeholder for SQL Injection functionality
    elif choice == "3":
        print("Exiting...")
        return False
    else:
        print("Invalid choice. Please select a valid option.")
        time.sleep(2)
        print('\n'*3)
    return True


def xsser():
    print("\n" + "#"*50)
    print("             XSS VULNERABILITY SCANNER")
    print("#"*50)

    print("You can scan a target URL for Cross-Site Scripting (XSS) vulnerabilities.")
    print("Example URL: https://example.com/frame?query=")
    target_url = input("Enter target host URL: ")

    print("If you don't provide a wordlist, the default wordlist will be used.")
    wordlist = input("Enter wordlist path (leave empty for default): ")

    if not wordlist:
        wordlist = "xss_wordlist.txt"
        print(f"No wordlist provided. Using default: {wordlist}")

    print(f"\nScanning target URL: {target_url}")
    print(f"Using wordlist: {wordlist}")

    # Menu
    # ---------------------------------------------
    # Functionality


if __name__ == '__main__':
    while True:
        print_menu()
        desired_atk = input("Enter your choice: ")
        if not attack_choice(desired_atk):
            break
