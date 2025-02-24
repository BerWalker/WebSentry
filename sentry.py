import argparse
import sys
from scan import perform_scan
from utils import check_url_alive, load_headers, load_headers_from_file
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """
    Parses command-line arguments for the vulnerability scanner.

    Returns:
        Namespace: An object containing the parsed arguments from the command line.

    Raises:
        None: The function returns a parsed argument object.
    """
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - A tool to audit and identify vulnerabilities in web applications. Ensure you have authorization to scan the target system.",
        epilog="Example usage:\n  python3 sentry.py -a sqli -u https://example.com -w wordlists/sqli_payloads.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Define command-line arguments for the scanner
    parser.add_argument('-a', '--attack', choices=['xss', 'sqli'], required=False,
                        help="Type of attack to perform: xss - Cross-Site Scripting, sqli - SQL Injection.")
    parser.add_argument('-u', '--url', required=False,
                        help="Target URL to scan. Example format: https://example.com/test?query=")
    parser.add_argument('-w', '--wordlist', default=None,
                        help="Optional path to the payload list file. Default wordlist used based on attack type.")

    parser.add_argument('--header', action='append', help="Define custom headers in the format 'Header-Name: value'. Use multiple '--header' flags for multiple headers.")
    parser.add_argument('--header-file', type=str, help="Path to a file with custom headers. Each line should be in 'Header-Name: value' format.")

    return parser.parse_args()


if __name__ == '__main__':
    """
    The main entry point for the vulnerability scanner. Parses command-line arguments,
    displays a welcome message, and initiates the vulnerability scan based on the user's input.
    """
    print(Fore.LIGHTWHITE_EX + """
        ▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
        ▐██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗▌
        ▐██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝▌
        ▐██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ▌
        ▐██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ▌
        ▐╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ▌
        ▐ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ▌
        ▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
    """)

    try:
        # Parse the command-line arguments
        args = parse_arguments()

        # Ensure necessary parameters are provided
        if not args.attack or not args.url:
            print(Fore.YELLOW + "[!] Required parameters missing. Please provide the following details:")

        # Attack type selection if not specified in arguments
        if not args.attack:
            print("1. XSS - Cross-Site Scripting")
            print("2. SQL Injection")
            #print("3. LFI - Local File Inclusion")

            attack_choice = input(Fore.CYAN + "[*] Enter the number corresponding to the attack type (1/2): ")

            while attack_choice not in ['1', '2', '3']:
                print(Fore.RED + "Invalid choice. Please try again.")
                attack_choice = input(Fore.CYAN + "[*] Enter the number corresponding to the attack type (1/2): ")

            # Map input choice to attack type
            if attack_choice == '1':
                attack_type = 'xss'
                print(Fore.GREEN + "XSS - Cross-Site Scripting SELECTED")
            elif attack_choice == '2':
                attack_type = 'sqli'
                print(Fore.GREEN + "SQL Injection SELECTED")
            #elif attack_choice == '3':
            #    attack_type = 'lfi'
            #    print("LFI - Local File Inclusion SELECTED")
        else:
            attack_type = args.attack

        # Get the target URL
        if not args.url:
            target_url = input(Fore.CYAN + "[*] Enter the target URL (e.g., https://example.com/query?param=): ")
        else:
            target_url = args.url.strip()

        # Ensure the URL has the correct protocol (http or https)
        if not (target_url.startswith('http://') or target_url.startswith('https://')):
            target_url = 'https://' + target_url

        # Load the appropriate payload list based on the attack type
        payload_list = args.wordlist if args.wordlist else f'PayloadLists/{attack_type.upper()}.txt'

        custom_headers = {}

        # Check if custom headers are specified through a file
        if args.header_file:
            custom_headers = load_headers_from_file(args.header_file)

        # Check if custom headers are provided via arguments
        if args.header:
            custom_headers = load_headers(args.header)

        # Verify if the target URL is alive and reachable
        if check_url_alive(target_url):
            # Perform the scan using the chosen attack type and headers
            if custom_headers:
                results = perform_scan(attack_type.upper(), target_url, payload_list, custom_headers)
            else:
                results = perform_scan(attack_type.upper(), target_url, payload_list)

    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
