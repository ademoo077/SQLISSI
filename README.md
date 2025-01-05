# SQLmap-like Tool

![SQLmap-like](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green)

SQLmap-like is a Python-based SQL Injection scanning tool inspired by sqlmap, developed as a university project. This educational tool replicates core functionalities of the popular SQLmap while offering flexibility, customization, and enhanced usability for penetration testers and ethical hackers. It also serves as a learning platform to understand SQL injection testing concepts. ⚠️ Use this tool responsibly and only in environments where you have explicit permission.---
## Project Information

**Developed by:**
- Omeiri
- Hezil
- Rezig

This tool was created as an educational exercise to understand the mechanics of SQL injection testing and automated security assessment tools. While inspired by SQLmap, it serves as a learning implementation with a focused feature set.

---

## **Features**

- Supports both `GET` and `POST` HTTP methods.
- Multiple SQL Injection testing techniques (e.g., blind, union-based, and time-based).
- URL crawling to discover hidden endpoints.
- Proxy support for anonymity.
- User-Agent rotation.
- Export results in **JSON** or **HTML** formats.

---
## Requirements

```bash
pip install -r requirements.txt
```


## Usage

Basic command structure:
```bash
python scanqli.py -u <target_url> -p <parameter> [options]
```
### **Options**

| **Argument**              | **Required** | **Description**                                                                                  |
|---------------------------|--------------|--------------------------------------------------------------------------------------------------|
| `-u`, `--url`             | Yes          | Target URL to scan (e.g., `http://example.com/page.php?id=1`).                                   |
| `-p`, `--param`           | Yes          | Vulnerable parameter to test (e.g., `id`).                                                      |
| `-m`, `--method`          | No           | HTTP method to use (`GET` or `POST`). Default: `GET`.                                           |
| `-t`, `--threads`         | No           | Number of concurrent threads. Default: `10`.                                                   |
| `--timeout`               | No           | Timeout for HTTP requests in seconds. Default: `10`.                                            |
| `--proxies`               | No           | Proxy URL (e.g., `http://127.0.0.1:8080`).                                                      |
| `--user-agents`           | No           | Rotate through a list of custom User-Agents.                                                   |
| `-o`, `--output`          | No           | Output file to save results (`.json` or `.html`).                                               |
| `--crawl`                 | No           | Enable crawling to discover additional URLs.                                                   |
| `--depth`                 | No           | Crawling depth. Default: `2`.                                                                   |
| `--tests`                 | No           | Specific tests to run (e.g., `basic`, `union`, `blind`). Default: all tests.                    |
| `--db`                    | No           | Target a specific database.                                                                     |
| `--tbl`                   | No           | Target a specific table.                                                                        |
| `--post-data`             | No           | POST data in `key=value&key2=value2` format. Required if `--method POST` is used.               |





#### Test Selection

Available test types:
- basic
- blind
- timebase
- gbkquotes
- allalpha
- union
- banner
- current_user
- current_database
- hostname
- dbs_count
- dbs_names
- tbls_count
- tbls_names
- cols_count
- cols_names

### Example Commands

1. Basic GET parameter scan:
```bash
python scanqli.py -u "http://example.com/page.php?id=1" -p id
```

2. POST request with custom data:
```bash
python scanqli.py -u "http://example.com/login.php" -p username -m POST --post-data "username=test&password=test"
```

3. Advanced scan with proxy and specific tests:
```bash
python scanqli.py -u "http://example.com/page.php?id=1" -p id --proxies "http://127.0.0.1:8080" --tests basic blind union --output results.json
```

4. Crawl and scan with custom depth:
```bash
python scanqli.py -u "http://example.com" -p id --crawl --depth 3 -t 20
```

## Output

The tool provides two output formats:
- JSON: Detailed technical output suitable for further processing
- HTML: Formatted report with visual presentation of findings

Results include:
- Vulnerability type
- Injection point
- Exploitation details
- Database information (when available)
- Execution time and statistics

## Educational Purpose

This tool was developed as an educational project to understand:
- SQL injection detection mechanisms
- Web application security testing
- Python programming for security tools
- Automated vulnerability scanning concepts

## Legal Disclaimer

This tool is provided for educational purposes only and should only be used in authorized testing environments. As a university project, it should not be used in production environments or against systems without explicit permission. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

- Inspired by the SQLmap project (https://github.com/sqlmapproject/sqlmap)
- Developed as a university project by Omeiri, Hezil, and Rezig
