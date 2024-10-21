from dns import DNS
from spider import target_links, crawl
from sqli import check_urls_from_list
from sqlauto import SQLMapAutomation
from lfi import load_payloads, check_urls_for_lfi
from xsss import xss_load_payloads, check_urls_for_xss
from colorama import init, Fore, Style
import html
import requests
import pyfiglet

init()


header = pyfiglet.figlet_format("VulnDetector")
sub_header = "developed by rshrakib"

print(header)
print(sub_header)

# SQL Injection effects and prevention
sql_effect = (
    "SQL INJECTION IMPACT: A SQL injection attack consists of insertion or “injection” of a SQL query "
    "via the input data from the client to the application. A successful SQL injection exploit can read "
    "sensitive data from the database, modify database data (Insert/Update/Delete), execute administration "
    "operations on the database (such as shutdown the DBMS), recover the content of a given file present "
    "on the DBMS file system and in some cases issue commands to the operating system."
)
sql_prevention = (
    "SQL INJECTION PREVENTION: To prevent SQL injection, use prepared statements with parameterized queries "
    "to ensure input is treated as data, not executable code. Always validate and sanitize user inputs, "
    "limiting what is accepted and rejecting anything unexpected. Employ least-privilege access for database "
    "accounts, ensuring they only have the necessary permissions."
)

# LFI effects and prevention
lfi_effect = (
    "LFI IMPACT: Local File Inclusion (LFI) can have serious impacts on a web application and its server. "
    "An attacker can exploit LFI to access sensitive files, such as configuration files or system logs, "
    "potentially revealing credentials or other critical information. LFI can also lead to code execution "
    "if the attacker manages to include malicious files, escalating the attack to a remote code execution (RCE)."
)
lfi_prevention = (
    "LFI PREVENTION: To prevent Local File Inclusion (LFI) attacks, validate and sanitize all user inputs, "
    "ensuring that only expected, safe file paths are allowed. Implement strict whitelisting for file names or "
    "paths and avoid using direct user input in file inclusion logic."
)

# XSS effects and prevention
xss_effect = (
    "XSS IMPACT: Cross-Site Scripting (XSS) attacks can have severe impacts on both users and web applications. "
    "Attackers can steal sensitive data like cookies, session tokens or login credentials by injecting malicious scripts "
    "into trusted websites. XSS can also allow an attacker to impersonate the victim or perform unauthorized actions."
)
xss_prevention = (
    "XSS PREVENTION: To prevent Cross-Site Scripting (XSS) attacks, sanitize and validate all user inputs to ensure "
    "they do not contain malicious scripts. Use Content Security Policy (CSP) headers to restrict the sources from "
    "which scripts can be loaded."
)

# Define the target domain
domain = input("[+] Enter your Domain >>>  ")

# Initialize DNS and crawl
dns = DNS()
print("\n[+] Server name and server version.....")
try:
    webversion = dns.web_server(domain)
except Exception as e:
    webversion = f"Error retrieving web server version: {str(e)}"
print(webversion)

print(Fore.GREEN + "[+][+] Domain crawling running..... " + Style.RESET_ALL)
crawl(domain, domain)

count = len(target_links)
print(Fore.GREEN + f"\n\n[+] Total {count} links found!!!" + Style.RESET_ALL)
print("=" * 50)

# Check for SQL injection vulnerabilities
print("\n[+][+] Checking for SQL injection vulnerabilities......")
print("_" * 50)
sql_vulnerable_urls, sqlcount = check_urls_from_list(target_links)
print(f"Total {sqlcount} url found for SQL injection.")

if sql_vulnerable_urls:
    sql_url = sql_vulnerable_urls[0]
    database = SQLMapAutomation(sql_url)
    database.run()
    print(Fore.RED + "\nSQL Injection Vulnerable URLs:" + Style.RESET_ALL)
    for vulnerable_url in sql_vulnerable_urls:
        print(vulnerable_url)
else:
    print("\n[+] No vulnerable URLs found For SQL injection.")
print("=" * 50)

# Check for LFI vulnerabilities
print("[+][+] Checking for LFI (Local File Inclusion) vulnerabilities:")
print("_" * 50)
payload_file_path = 'lfi_payload.txt'
payload_list = load_payloads(payload_file_path)
lfi_vulnerable_urls, lficount = check_urls_for_lfi(target_links, payload_list)
print(f"[+][+] Total {lficount} urls found for LFI vulnerabilities...")
if lfi_vulnerable_urls:
    for url in lfi_vulnerable_urls:
        print(f"URL: {url}")
else:
    print(Fore.GREEN + "\n[+] No vulnerable URLs found." + Style.RESET_ALL)
print("+" * 50)

# Check for XSS vulnerabilities
print("\n[+][+] Check for Reflected-XSS vulnerabilities....")
print("_" * 30)
xss_payload_file_path = 'xss_payload.txt'
xss_payload_list = xss_load_payloads(xss_payload_file_path)
xss_vulnerable_urls, xsscount = check_urls_for_xss(target_links, xss_payload_list)
print(f"[+][+] Total {xsscount} urls found for XSS vulnerabilities...")
if xss_vulnerable_urls:
    for url in xss_vulnerable_urls:
        print(f"URL: {url}")
else:
    print(Fore.GREEN + "\n[+] No vulnerable URLs found." + Style.RESET_ALL)
print("+" * 50)

# Generate the HTML report
html_report_file_name = f"{domain.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
with open(html_report_file_name, 'w') as report_file:
    report_file.write("<html>\n<head>\n<title>Security Report</title>\n</head>\n<body>\n")
    report_file.write(f"<h1>Security Report for {domain}</h1>\n")
    report_file.write(f"<h2>Total Links Found</h2>\n<p>Total {count} links found!!!</p>")
    report_file.write("<h2>Links Found:</h2>\n<ul>\n")
    for url in target_links:
        report_file.write(f"<li>{html.escape(url)}</li>\n")
    report_file.write("</ul>\n")

    report_file.write("<h2>SQL Injection</h2>\n")
    report_file.write(f"<p>{html.escape(sql_effect)}</p>\n")
    report_file.write(f"<p>Total {sqlcount} URLs found for SQL injection.</p>\n")
    if sql_vulnerable_urls:
        sql_url = sql_vulnerable_urls[0]
        database = SQLMapAutomation(sql_url)
        report_file.write(f"<h2>Databases Found: </h2><br> <ln>{database.run()}</ln>")
        report_file.write("<h3>Vulnerable URLs:</h3>\n<ul>\n")
        for url in sql_vulnerable_urls:
            report_file.write(f"<li>{html.escape(url)}</li>\n")
    else:
        report_file.write("<li>No vulnerable URLs found for SQL injection.</li>\n")
    report_file.write("</ul>\n")
    report_file.write(f"<p>{html.escape(sql_prevention)}</p>\n")

    report_file.write("<h2>Local File Inclusion (LFI)</h2>\n")
    report_file.write(f"<p>{html.escape(lfi_effect)}</p>\n")
    report_file.write(f"<p>Total {lficount} URLs found for LFI vulnerabilities...</p>\n")

    if lfi_vulnerable_urls:
        response_lfi = requests.get(lfi_vulnerable_urls[0][0])
        report_file.write(f"<h2>URL Response: </h2> \n <ln>{html.escape(response_lfi.text)}</ln>")
        report_file.write("<h3>Vulnerable URLs:</h3>\n<ul>\n")
        for url in lfi_vulnerable_urls:
            if isinstance(url, tuple):
                url = url[0]
            report_file.write(f"<li>{html.escape(url)}</li>\n</ul>")
    else:
        report_file.write("<li>No vulnerable URLs found.</li>\n")
    report_file.write(f"<p>{html.escape(lfi_prevention)}</p>\n")

    report_file.write("<h2>Cross-Site Scripting (XSS)</h2>\n")
    report_file.write(f"<p>{html.escape(xss_effect)}</p>\n")
    report_file.write(f"<p>Total {xsscount} URLs found for XSS vulnerabilities...</p>\n")

    if xss_vulnerable_urls:
        response_xss = requests.get(xss_vulnerable_urls[0][0])
        report_file.write(f"<h2>URL Response: </h2> \n <ln>{html.escape(response_xss.text)}</ln>")
        report_file.write("<h3>Vulnerable URLs:</h3>\n<ul>\n")
        for url in xss_vulnerable_urls:
            if isinstance(url, tuple):
                url = url[0]
            report_file.write(f"<li>{html.escape(url)}</li></ul>\n")
    else:
        report_file.write("<li>No vulnerable URLs found.</li>\n")
    report_file.write(f"<p>{html.escape(xss_prevention)}</p>\n")

    report_file.write("<li>Thank you. Have a Good Day.</li>\n")
    report_file.write("<h6>Developed By MD. Rakibul Hasan, CSE_BRUR</h6>\n")
    report_file.write("</body>\n</html>")

print(Fore.GREEN + f"[+] Report saved as {html_report_file_name}" + Style.RESET_ALL)
