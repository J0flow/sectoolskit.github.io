import requests
from bs4 import BeautifulSoup
import re

def get_ip_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        country = data.get('country', 'N/A')
        return country
    else:
        return None

def analyze_ip(ip_address):
    url = f'https://scamalytics.com/ip/{ip_address}'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    score_element = soup.find('div', {'class': 'score'})
    score = score_element.text.strip() if score_element else 'Not Found'
    score = score.replace('Fraud Score:', '').strip()
    return score

def check_vpn(ip_address):
    url = f'https://proxycheck.io/v2/{ip_address}'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if ip_address in data and 'proxy' in data[ip_address]:
            return data[ip_address]['proxy'] == 'yes'
        else:
            return False
    else:
        return False

def parse_dhcp_message(dhcp_message):
    offer_match = re.search(r'DHCPOFFER on ([\d\.]+) to ([\w:]+) \(([\w-]+)\)', dhcp_message)
    request_match = re.search(r'DHCPREQUEST for ([\d\.]+) from ([\w:]+) \(([\w-]+)\)', dhcp_message)
    
    if offer_match:
        ip_address = offer_match.group(1)
        mac_address = offer_match.group(2)
        hostname = offer_match.group(3)
        action = "DHCPOFFER"
    elif request_match:
        ip_address = request_match.group(1)
        mac_address = request_match.group(2)
        hostname = request_match.group(3)
        action = "DHCPREQUEST"
    else:
        return None, None, None, None
    
    return ip_address, hostname, mac_address, action
