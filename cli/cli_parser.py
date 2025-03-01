import argparse

class CLIParser:
    def __init__(self):
        # Initialize the ArgumentParser with a description, example, and custom formatting
        self.parser = argparse.ArgumentParser(
            description="Web Vulnerability Scanner",  # Brief description of the tool
            epilog="Example: python3 main.py -a sqli -u https://example.com",  # Example usage shown after help
            formatter_class=argparse.RawTextHelpFormatter  # Preserve formatting in help text
        )
        # Call the method to define all command-line arguments
        self._setup_arguments()

    def _setup_arguments(self):
        # Define the argument for selecting the attack type (xss or sqli)
        self.parser.add_argument('-a', '--attack', choices=['xss', 'sqli'], required=False,
                            help="Type of attack to perform: xss - Cross-Site Scripting, sqli - SQL Injection.")

        # Define the argument for specifying the target URL
        self.parser.add_argument('-u', '--url', required=False,
                            help="Target URL to scan. Example format: https://example.com/test?query=")

        # Define the argument for an optional custom payload wordlist
        self.parser.add_argument('-w', '--wordlist', default=None,
                            help="Optional path to the payload list file. Default wordlist used based on attack type.")

        # Define the argument for adding custom headers (can be used multiple times)
        self.parser.add_argument('--header', action='append',
                            help="Define custom headers in the format 'Header-Name: value'. Use multiple '--header' flags for multiple headers.")

        # Define the argument for loading headers from a file
        self.parser.add_argument('--header-file', type=str,
                            help="Path to a file with custom headers. Each line should be in 'Header-Name: value' format.")

        # Define output options for different file formats
        self.parser.add_argument('-o', '--output', type=str, help="Export results in plain text format.")
        self.parser.add_argument('-oJ', '--output-json', type=str, help="Export results in JSON format.")
        self.parser.add_argument('-oX', '--output-xml', type=str, help="Export results in XML format.")

    def parse_arguments(self):
        # Parse and return the command-line arguments provided by the user
        return self.parser.parse_args()