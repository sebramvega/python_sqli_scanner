# SQL Injection Scanner

This project is a Python-based tool that scans web forms for potential SQL injection vulnerabilities. It uses `requests` and `BeautifulSoup` libraries to interact with websites and parse HTML content, respectively.

## Features

- **Fetches and Analyzes Forms**: Automatically finds all forms on a given webpage.
- **SQL Injection Testing**: Tests each form for common SQL injection vulnerabilities.
- **Logging**: Logs detailed information about the scanning process, including potential vulnerabilities detected.
- **User Input**: Allows users to input the URL of the website to be scanned.

## Requirements

- Python 3.11 or later
- `requests` library
- `beautifulsoup4` library

## How to Run

- Run the script:

```bash
python scan.py
```

- Then, enter the URL of the webstite you want to scan:

```bash
Enter the URL to be checked: https://example.com
```

- The tool will scan the website's forms for SQL injection vulnerabilities. Results will be logged in sql_injection_scan.log

### Sample Output

After running the script, you will see a summary message in the terminal, such as:

```bash
3 forms checked, NO vulnerabilities found. Check log file for details
```

Or, if vulnerabilities were detected:

```bash
Vulnerabilities found in forms on https://example.com. Check log file for details.
```

## Logging

All the Detailed logs are saved to a `sql_injection_scan.log` file. This include:

- Number of forms found.
- Form details.
- Pauloads tested.
- Any potential vulnerabilities detected.

## License

This project is open-source and available under the **MIT License**.
