# Sentry Web Vulnerability Scanner

Sentry is a tool designed to audit and identify common vulnerabilities in web applications. It can be used to scan a target website by injecting various payloads into query strings and analyzing the responses.

Important: Ensure that you have authorization to scan the target web application. Unauthorized usage is illegal and unethical.

## Features

- **XSS (Cross-Site Scripting) Detection**: Scans for Cross-Site Scripting (XSS) vulnerabilities by injecting XSS payloads into the target URL's query string and detecting script execution on the page.
- **SQL Injection (SQLi) Detection**: Identifies SQL Injection vulnerabilities by injecting SQL-specific payloads into the URL query string and checking for database error patterns or unexpected behavior.
- **Wordlist-based Attacks**: Uses a list of payloads (either provided by the user or default) for testing vulnerabilities.
- **Custom Headers**: Supports adding custom HTTP headers for each scan, either individually or through a file, allowing greater control over the request configurations.
- **Selenium Integration**: Uses Selenium WebDriver to interact with dynamic content, making it possible to detect vulnerabilities like XSS that rely on JavaScript execution.

## Requirements

- Python 3.x
- `requests` library (version 2.32.0 or higher)
- `selenium` library (version 4.28.0 or higher)
- `selenium-wire` library (version 5.1.0 or higher)
- `setuptools` library (version 75.8.0 or higher)

To install the required dependencies, run:

```bash
pip install -r requirements.txt
```

## Usage

1. **Start the Scanner**:

```bash
git clone https://github.com/berwalker/websentry.git
cd /your/path/WebSentry
```

2. **Run the Scan**:

```bash
python ./sentry.py [-h] [-a {xss,sqli}] [-u URL] [-w WORDLIST] [--header HEADER] [--header-file HEADER_FILE]
```

- -a, --attack: Type of scan to perform.
- -u, --url: Target URL to scan, e.g., https://example.com/query=.
- -w, --wordlist: Path to a custom payload list file. If not specified, the default payload list for the selected attack type will be used.
- --header: Custom headers in (Header-Name: value) format. This option can be specified multiple times to add multiple headers.
- --header-file: Path to a file with custom headers. Each line should follow the format (Header-Name: value).
- -h, --help: Displays a help message with descriptions of all options and examples for usage.

3. **Examples**:

```bash
python ./sentry.py -a sqli -u https://example.com/page?query= --header "User-Agent: CustomAgent/1.0" --header "Authorization: token123"
```
```bash
python ./sentry.py -a xss -u https://example.com/page?query= --header-file headers.txt -w /Path/to/Wordlist.txt
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


