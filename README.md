# Sentry Web Vulnerability Scanner

Sentry is a simple web vulnerability scanner designed to identify potential security weaknesses in web applications. It currently supports scanning for Cross-Site Scripting (XSS) and SQL Injection vulnerabilities.

## Features

- **Cross-Site Scripting (XSS)**: Scans for XSS vulnerabilities by injecting payloads into web input fields and analyzing the responses.
- **SQL Injection**: Detects potential SQL Injection vulnerabilities by injecting payloads into query parameters and examining the server responses.
- **User-friendly Menu**: Interactive command-line interface for selecting the type of scan and input parameters.
- **Custom Payload Lists**: Allows the use of custom payload lists for scanning.

## Requirements

- Python 3.x
- `requests` library (version 2.32.0 or higher)
- `beautifulsoup4` library (version 4.12.0 or higher)

To install the required dependencies, run:

```bash
pip install -r requirements.txt
```

 (we expect you to have Python 3.x installed )

## Usage

1. **Start the Scanner**: Run the `main.py` script to begin. In your terminal, execute:

```bash
git clone https://github.com/berwalker/websentry.git
cd /your/path/WebSentry
python main.py
```

3. **Select Scan Type**:
   - **1**: Cross-Site Scripting (XSS)
   - **2**: SQL Injection
   - **3**: Exit

4. **Enter Target URL**: Provide the URL of the target web application you wish to scan.

5. **Provide Payload List**: Optionally, specify the path to a custom payload list. If left empty, the default payload list will be used.

6. **Review Results**: The scanner will output the results of the scan, highlighting potential vulnerabilities.

## Example

```
##################################################
            WEB VULNERABILITY SCANNER
##################################################
Select the desired attack:
1. Cross-Site Scripting (XSS)
2. SQL Injection
3. Exit
Enter your choice: 1

Cross-Site Scripting (XSS) selected.

##################################################
          XSS VULNERABILITY SCANNER
##################################################
Enter target host URL (e.g., https://example.com/page or https://example.com/test?query=): https://example.com
0000-00-00 00:00:00 - INFO - URL is reachable: https://google.com
Enter payload-list path (leave empty for default):
No wordlist provided. Using default: PayloadLists/xss.txt
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


