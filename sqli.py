import requests
import re
from colorama import init, Fore, Style
init()
def check_sql_injection(url):
    try:
        original_response = requests.get(url)
        
        url_with_quote = url + "'"
        modified_response = requests.get(url_with_quote)
        
        if original_response.text != modified_response.text:
            return True
        else:
            return False 
    except requests.RequestException as e:
        # print(Fore.RED + f"\n[-] Error checking URL {url}: {e}" + Style.RESET_ALL)
        return False

def identify_target_urls(url_list):
    pattern = re.compile(r'\?.+=.+')
    target_urls = [url for url in url_list if re.search(pattern, url)]
    return target_urls

def check_urls_from_list(url_list):
    vulnerable_urls = []
    target_urls = identify_target_urls(url_list)
    sql_count = 0
    for url in target_urls:
        if check_sql_injection(url):
            sql_count += 1
            print(f"Total {sql_count} urls for SQL injection", end="\r")
            vulnerable_urls.append(url)
        # else:
            # print(Fore.RED + f"[+] Safe: {url}" + Style.RESET_ALL)
    
    return vulnerable_urls,sql_count
