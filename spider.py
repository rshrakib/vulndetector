import re
import requests
import urllib.parse as urlparse
from colorama import init, Fore, Style
target_links = []

def extract_links(url):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        return re.findall(r'href="(.*?)"', response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return []

def crawl(url, target_url):
    href_links = extract_links(url)
    for link in href_links:
        full_link = urlparse.urljoin(url, link)
        
        if 'logout' in full_link.lower() or 'signout' in full_link.lower():
            continue

        if '#' in full_link:
            full_link = full_link.split("#")[0]

        if target_url in full_link and full_link not in target_links:
            target_links.append(full_link)
            crawl(full_link, target_url) 
# domain = "http://172.16.67.140/mutillidae/"
# print(Fore.GREEN+ "[+][+] Domain crawling running..... " + Style.RESET_ALL)
# crawl(domain, domain)
#
# count = 0
# for link in target_links:
#     # print(link)
#     count+=1
# print(Fore.GREEN + f"\n\n[+]Total {count} links found!!!" + Style.RESET_ALL)
# print("=" * 50)
# print("=" * 50)