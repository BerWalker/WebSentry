# Sentry Web Vulnerability Scanner

Sentry is a simple web vulnerability scanner designed to identify potential security weaknesses in web applications. It currently supports detecting vulnerabilities such as Reflected XSS and Error-Based SQL Injection.

## Features

- **Reflected Cross-Site Scripting (XSS)**: Scans for reflected XSS vulnerabilities.
- **Error-Based SQL Injection**: Detects error-based SQL injection vulnerabilities for MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and Generic error messages.
- **Input Field Discovery**: Automatically detects input fields (such as query parameters, form inputs, etc.) on the target page to test for vulnerabilities.
- **Direct Query Support**: Allows the user to specify a direct query (e.g., URL with parameters or form data) for targeted scanning, bypassing the need for the scanner to find inputs on its own.
- **Custom Payload Lists**: Allows the use of custom payload lists for scanning.
- **Custom Headers**: Supports adding custom HTTP headers for each scan, either individually or through a file, allowing greater control over the request configurations.
- **Export Results in Multiple Formats**: Export scan results in plain text, JSON, or XML formats for greater flexibility.

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

2. **Run the Scan**: Execute the scanner by specifying the attack type, target URL, and optionally the wordlist file path, as well as custom headers if needed. You can also specify output parameters to generate reports in plain text, XML, or JSON formats:

```bash
python sentry.py -a <attack_type> -u <target_url> [-w <wordlist_path>] [--header <Header-Name: value>] [--header-file <path_to_header_file>] [-o <output_filename>] [-oX <output_filename>] [-oJ <output_filename>]
```

- -a, --attack: Type of scan to perform (xss for Cross-Site Scripting or sqli for SQL Injection).
- -u, --url: Target URL to scan, e.g., https://example.com.
- -w, --wordlist (optional): Path to a custom payload list file. If not specified, the default payload list for the selected attack type will be used.
- --header (optional): Custom headers in (Header-Name: value) format. This option can be specified multiple times to add multiple headers.
- --header-file (optional): Path to a file with custom headers. Each line should follow the format (Header-Name: value).
- -o, --output (optional): Export results in plain text format with specified filename.
- -oX, --xml (optional): Export results in XML format with specified filename.
- -oJ, --json (optional): Export results in JSON format with specified filename.
- -h, --help: Displays a help message with descriptions of all options and examples for usage.

3. **Examples**:

```bash
python sentry.py -a sqli -u https://example.com -w wordlists/sqli_payloads.txt -o scanner_result.txt
```
```bash
python sentry.py -a xss -u https://example.com/page?query= --header "User-Agent: CustomAgent/1.0" --header "Authorization: token123"
```
```bash
python sentry.py -a xss -u https://example.com/page?query= --header-file headers.txt -oX scanner_result.xml
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


