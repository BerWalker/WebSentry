# Sentry Web Vulnerability Scanner

Sentry is a simple web vulnerability scanner designed to identify potential security weaknesses in web applications. It currently supports scanning for Cross-Site Scripting (XSS) and SQL Injection vulnerabilities.

## Features

- **Cross-Site Scripting (XSS)**: Scans for XSS vulnerabilities by injecting payloads into web input fields and analyzing the responses.
- **SQL Injection**: Detects potential SQL Injection vulnerabilities by injecting payloads into query parameters and examining the server responses.
- **Custom Payload Lists**: Allows the use of custom payload lists for scanning.
- **Custom Headers**: Supports adding custom HTTP headers for each scan, either individually or through a file, allowing greater control over the request configurations.

## Requirements

- Python 3.x
- `requests` library (version 2.32.0 or higher)
- `beautifulsoup4` library (version 4.12.0 or higher)

To install the required dependencies, run:

```bash
pip install -r requirements.txt
```

## Usage

1. **Start the Scanner**: Clone the repository and navigate to the directory in your terminal:

```bash
git clone https://github.com/berwalker/websentry.git
cd /your/path/WebSentry
```

2. **Run the Scan**: Execute the scanner by specifying the scan type, target URL, and optional payload list file, along with custom headers if required, as command-line arguments:

```bash
python main.py -a <attack_type> -u <target_url> [-w <wordlist_path>] [--header <Header-Name: value>] [--header-file <path_to_header_file>]
```

- -a, --attack: Type of scan to perform (xss for Cross-Site Scripting or sqli for SQL Injection).
- -u, --url: Target URL to scan, e.g., https://example.com.
- -w, --wordlist (optional): Path to a custom payload list file. If not specified, the default payload list for the selected attack type will be used.
- --header (optional): Custom headers in (Header-Name: value) format. This option can be specified multiple times to add multiple headers.
- --header-file (optional): Path to a file with custom headers. Each line should follow the format (Header-Name: value).
- -h, --help: Displays a help message with descriptions of all options and examples for usage.

3. **Examples**:

```bash
python main.py -a sqli -u https://example.com -w wordlists/sqli_payloads.txt
```
```bash
python main.py -a xss -u https://example.com/page?query= --header "User-Agent: CustomAgent/1.0" --header "Authorization: token123"
```
```bash
python main.py -a xss -u https://example.com/page?query= --header-file headers.txt
```


## Contributing

Contributions are welcome! If you want to contribute:

1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a Pull Request with a clear description of what was changed.

Thank you for contributing!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, feel free to get in touch:

- **Name:** Bernardo W. Leichtweis
- **Email:** [bernardoowalkerl@gmail.com](mailto:bernardoowalkerl@gmail.com)
- **LinkedIn:** [bernardo-w-leichtweis](https://www.linkedin.com/in/bernardo-w-leichtweis)


