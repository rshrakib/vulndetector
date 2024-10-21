import requests
import re
from colorama import init, Fore, Style

init()

def check_xss_vulnerability(url, payload):
    try:
        # Substitute payload into the URL
        url_with_payload = re.sub(r"(\?.*?=)([^&]*)", r"\1" + payload, url)
        response = requests.get(url_with_payload)

        # Check if the payload is in the response
        if payload in response.text:
            return True, url_with_payload
        else:
            return False, None
    except requests.RequestException as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return False, None

def identify_xss_target_urls(url_list):
    pattern = re.compile(r"(\?.*?=)([^&]*)")

    target_urls = [url.strip() for url in url_list if re.search(pattern, url)]
    return target_urls

def check_urls_for_xss(url_list, payload_list):
    vulnerable_urls = []
    xss_count = 0
    target_urls = identify_xss_target_urls(url_list)

    for url in target_urls:
        for payload in payload_list:
            is_vulnerable, checked_url = check_xss_vulnerability(url, payload)

            if is_vulnerable:
                xss_count += 1
                # print(f"{Fore.GREEN}Vulnerable URL found: {checked_url} with payload: {payload}{Style.RESET_ALL}")
                vulnerable_urls.append((checked_url, payload))
                break
        print(f"Total {xss_count} XSS vulnerabilities found...", end="\r")
    return vulnerable_urls, xss_count

def xss_load_payloads(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = file.readlines()
        return [payload.strip() for payload in payloads]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: The file '{file_path}' was not found.{Style.RESET_ALL}")
        return []
