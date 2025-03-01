from colorama import Fore
from utils.network import check_url_alive

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
    # Add HTTPS prefix if protocol is missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    # Check if URL is reachable; raise error if not
    if not check_url_alive(url):
        raise ValueError("URL not reachable")
    return url  # Return the validated URL