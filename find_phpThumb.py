from googlesearch import search
from fake_useragent import UserAgent
import requests
import time
import re
from tabulate import tabulate
from termcolor import colored
import sys
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def help():
    print("This script was created as a simple dork enumerator to find which domains are vulnerable to phpThumb based on its version. Here are some useful links that will help you out if you need to adjust/modify the script or read about the phpThumb function:\n")
    print("1) How to use python googlesearch module to scrape the web --> https://medium.com/@nutanbhogendrasharma/how-to-scrape-google-search-engines-in-python-44770b8eab5")
    print("2) Bonus docs for python googlesearch module --> https://python-googlesearch.readthedocs.io/en/latest/")
    print("3) phpThumb info (RCE) --> https://www.acunetix.com/vulnerabilities/web/phpthumb-fltr-parameter-command-injection-vulnerability/")
    print("4) phpThumb revshell exploit (RCE) --> https://www.exploit-db.com/exploits/38852")
    print("5) phpThumb revshell exploit (RCE) --> https://vulners.com/zdt/1337DAY-ID-21218")
    print("6) phpThumb info (SSRF) --> https://www.rafaybaloch.com/2017/06/phpThumb-Server-Side-Request-Forgery.html")

    print("Now, let's search some domains\n")


def vuln(x_value):
    if x_value != None:
        value = int(x_value)
        if value <= 9:
            return "RCE"
        if value == 12:
            return "SSRF"
    return None



def isVulnerable(full_version):
    pattern = r'v1\.7\.(\d+)-\d+'
    match = re.search(pattern, full_version)
    if match:
        x_value = match.group(1)
        return x_value
    return None

def findVersion(key, resp_txt):
    pattern = r'phpThumb\(\) v1\.7\..*?\n'
    match = re.search(pattern, resp_txt)
    if match:
        matched_text = match.group()
        full_version = matched_text[len("phpThumb() "):]
        x_value = isVulnerable(full_version)
        return full_version, x_value
    return None, None


try:
    query = 'inurl:"/phpThumb.php?src="'
    if len(sys.argv) < 2:
        print("Usage: python find_phpThumb.py [number_of_domains_to_be_found]")
        sys.exit(1)

    help()
    num_results = int(sys.argv[1])
    user_agent = UserAgent()

    results = search(query, sleep_interval=0.2, num_results=num_results)
    urls = {}
    for url in results:
        if '/phpThumb.php?src' in url:
            path = url[:url.index('/phpThumb.php?src') + len('/phpThumb.php?src')] + '='
            urls[url] = path
    

    versions = {}
    for key in urls.keys():
        headers = {'User-Agent': user_agent.random}
        response = requests.get(urls[key], headers=headers, verify=False)
        time.sleep(0.5)
        full_version, x_value = findVersion(key, response.text)
        versions[key] = [full_version, vuln(x_value)]

    table_data = []
    for key in urls.keys():
        path = urls[key]
        full_version = versions[key][0]
        vuln_status = versions[key][1]

        if vuln_status == "RCE":
            vuln_status = colored(vuln_status, 'red')
        elif vuln_status == "SSRF":
            vuln_status = colored(vuln_status, 'yellow')
        else:
            vuln_status = colored('Not found', 'white')

        if full_version == None:
            full_version = colored('Not found', 'white')

        table_data.append([path, full_version, vuln_status])

    table_headers = [colored("domain", 'white', 'on_grey', attrs=['bold']),
                     colored("Version", 'white', 'on_grey', attrs=['bold']),
                     colored("vulnerability", 'white', 'on_grey', attrs=['bold'])]

    # Generate the table using tabulate
    table = tabulate(table_data, headers=table_headers, tablefmt="grid", stralign="center")

    print(table)

except Exception as e:
    print(f"An error occurred: {e}")
