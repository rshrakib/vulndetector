import requests
import re
from colorama import init, Fore, Style
init()

def check_lfi_vulnerability(url, payload):
    try:
        url_with_payload = re.sub(r'(\?.+=)(.+?\.\w+)', r'\1' + payload, url)
        response = requests.get(url_with_payload)

        if "root:" in response.text or "bin/bash" in response.text:
            return True, url_with_payload
        else:
            return False, None
    except requests.RequestException as e:
        # print(Fore.RED + f"Error checking URL {url} with payload {payload}: {e}" + Style.RESET_ALL)
        return False, None

def identify_lfi_target_urls(url_list):
    pattern = re.compile(r'\?.+=.+\.\w+')
    
    target_urls = [url.strip() for url in url_list if re.search(pattern, url)]
    
    return target_urls

def check_urls_for_lfi(url_list, payload_list):
    vulnerable_urls = []
    lfi_count = 0
    target_urls = identify_lfi_target_urls(url_list)
    
    for url in target_urls:
        for payload in payload_list:
            url_with_payload = re.sub(r'(\?.+=)(.+?\.\w+)', r'\1' + payload, url)
            
            # print(f"Checking URL: {url_with_payload}", end='\r') 
            is_vulnerable, checked_url = check_lfi_vulnerability(url, payload)
            
            if is_vulnerable:
                # print()
                # print(Fore.RED + f"[!] Potential LFI vulnerability found: {checked_url} with payload {payload}" + Style.RESET_ALL)
                lfi_count += 1
                print(f"Total {lfi_count} urls found for LFI vulnerabilities...", end = "\r")
                vulnerable_urls.append((checked_url, payload))
                break 
    return vulnerable_urls,lfi_count

def load_payloads(file_path):
    with open(file_path, 'r') as file:
        payloads = file.readlines()
    return [payload.strip() for payload in payloads]
