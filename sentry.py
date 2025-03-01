import sys
from cli.cli_parser import CLIParser
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from utils.io_utils import export_results, load_headers, load_headers_from_file
from utils.prompt import prompt_attack_type, prompt_url
from colorama import init, Fore

# Initialize colorama for colored terminal output
init(autoreset=True)

def main():
    # Create an instance of CLIParser to handle command-line arguments
    parser = CLIParser()
    args = parser.parse_arguments()

    # Display a stylized banner for the tool
    print(Fore.LIGHTWHITE_EX + """
            ▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
            ▐██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗▌
            ▐██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝▌
            ▐██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ▌
            ▐██║███╗██║██╔══╝  ██╔==██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ▌
            ▐╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ▌
            ▐ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ▌
            ▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
        """)

    # Check if required arguments (attack type and URL) are provided
    if not args.attack or not args.url:
        print(Fore.YELLOW + "[!] Required parameters missing. Please provide the following details:")

    # Define a mapping of attack types to their respective scanner classes
    scanner_map = {
        'xss': XSSScanner,
        'sqli': SQLiScanner
    }

    # Get attack type and target URL, either from arguments or user prompts
    attack_type = args.attack or prompt_attack_type()
    target_url = args.url or prompt_url()

    # Ensure the URL has a valid protocol prefix (http:// or https://)
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    # Select the appropriate scanner class based on the attack type
    scanner_class = scanner_map.get(attack_type.lower())

    # Set the payload list file path, defaulting to a predefined file if not provided
    payload_list = args.wordlist or f'PayloadLists/{attack_type.upper()}.txt'

    custom_headers = None

    # Load custom headers from a file if specified
    if args.header_file:
        custom_headers = load_headers_from_file(args.header_file)

    # Load custom headers from command-line argument if provided
    if args.header:
        custom_headers = load_headers(args.header)

    # Instantiate the scanner with the target URL, payload list, and headers
    scanner = scanner_class(target_url, payload_list, headers=custom_headers)

    # Start the scanning process and display progress
    print(Fore.CYAN + "[*] Starting scan...")
    results = scanner.scan()
    print(Fore.CYAN + "[*] Scan completed.")

    # Export scan results to files in specified formats if requested
    if args.output:
        export_results(results, args.output, "plain")
    if args.output_json:
        export_results(results, args.output_json, "json")
    if args.output_xml:
        export_results(results, args.output_xml, "xml")

if __name__ == "__main__":
    try:
        # Run the main function
        main()
    except KeyboardInterrupt:
        # Handle manual interruption (e.g., Ctrl+C) gracefully
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        # Catch and report any unexpected errors
        print(Fore.RED + f"[!] Unexpected error: {e}")
        sys.exit(1)