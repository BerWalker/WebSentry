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


def prompt_attack_type():
    # Display attack type options
    print("1. XSS - Cross-Site Scripting\n2. SQL Injection")
    choice = input(Fore.CYAN + "[*] Enter attack type (1/2): ")
    # Validate user input
    while choice not in ['1', '2']:
        print(Fore.RED + "[!] Invalid attack type.")
        choice = input(Fore.CYAN + "[*] Enter attack type (1/2): ")
    if choice == '1':
        # Confirm XSS selection
        print(Fore.GREEN + "[+] Cross-Site Scripting SELECTED")
        return 'xss'
    if choice == '2':
        # Confirm SQL Injection selection
        print(Fore.GREEN + "[+] SQL Injection SELECTED")
        return 'sqli'


def prompt_url():
    # Prompt user for a target URL
    url = input(Fore.CYAN + "[*] Enter target URL: ").strip()
    return url  # Return the validated URL
