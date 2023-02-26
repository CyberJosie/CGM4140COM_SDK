import requests
import json
from requests import session
from bs4 import BeautifulSoup

def cleanval(val: str) -> str:
    repl = {
        # ' ': '',
        '\t': '',
        '\r': '',
        '\n': '',
    }
    for k in list(repl.keys()):
        val = val.replace(k, repl[k]).strip()
    return val


class CoxGatewaySDK:
    def __init__(self, host: str = '192.168.0.1'):
        self.host = host
        self.session_cookie = None
        self.sess = requests.session()

    def has_session(self) -> bool:
        return True if self.session_cookie != None else False

    def authenticate(self, username: str, password: str) -> bool:
        logged_in = False
        session_cookie = None

        url_enc_data = 'username={}&password={}&locale=false'.format(
            username, password)

        headers = {
            'Host': self.host,
            'Content-Length': str(len(url_enc_data)),
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Origin': 'http://{}'.format(self.host),
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Referer': 'http://{}'.format(self.host),
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }

        params = {
            'username': username,
            'password': password,
            'locale': False,
        }

        url = 'http://{}/check.jst'.format(self.host)
        try:
            r = self.sess.post(url, headers=headers, data=params)

            if 'Set-Cookie' in list(r.headers.keys()):
                session_cookie = r.headers.get('Set-Cookie')
                logged_in = True
        except Exception as e:
            print("Error logging in: {}".format(str(e)))
        self.session_cookie = session_cookie
        return logged_in

    def devices(self) -> dict:
        devices = {
            'online': [],
            'offline': [],
        }
        url = 'http://{}/connected_devices_computers.jst'.format(self.host)

        if not self.has_session():
            print("You need to authenticate first!")
            return []

        headers = {
            'Host': self.host,
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Referer': 'http://{}'.format(self.host),
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
            'Cookie': self.session_cookie,
        }

        url = 'http://{}/connected_devices_computers.jst'.format(self.host)
        try:
            r = self.sess.post(url, headers=headers)

            soup = BeautifulSoup(str(r.content.decode()), 'html.parser')

            # Parse online device rows
            online_device_block = soup.find(
                'div', id='online-private')
            online_device_rows = online_device_block.find_all('tr')

            # Parse offline device rows
            offline_device_block = soup.find(
                'div', id='offline-private')
            offline_device_rows = offline_device_block.find_all('tr')

            # Parse data from online devices
            for odr in online_device_rows:
                rsoup = BeautifulSoup(str(odr), 'html.parser')
                try:
                    hostname_block = rsoup.find(
                        'td', headers='host-name')
                    name = rsoup.find(
                        'a', class_='label device-name private').text.replace('\r', '').replace('\t', '')
                    res_type = 'dhcp' if 'DHCP' in rsoup.find(
                        'td', headers='dhcp-or-reserved').text.upper() else 'static'
                    network = rsoup.find(
                        'td', headers='connection-type').text.replace(' ', '')
                    rssi_level = rsoup.find(
                        'td', headers='rssi-level').text.replace('\t', '')

                    ipv4_address = 'Unknown'
                    ipv6_address = 'Unknown'
                    mac_address = 'Unknown'

                    # advanced info
                    adv_info = hostname_block.find('div')
                    for child in adv_info.find_all('dd'):

                        if 'ipvaddloc' in str(child):
                            ipv4_address = str(child.next_sibling)
                        if 'ipv6addloc' in str(child):
                            ipv6_address = str(child.next_sibling)
                        if 'macaddlocnew' in str(child):
                            mac_address = str(child.next_sibling)

                    devices['online'].append({
                        'name': name,
                        'lease_type': res_type,
                        'network': network,
                        'rssi': rssi_level,
                        'ipv4': ipv4_address,
                        'ipv6': ipv6_address,
                        'mac': mac_address,
                    })
                except Exception as e:
                    continue

            for odr in offline_device_rows:
                try:
                    rsoup = BeautifulSoup(str(odr), 'html.parser')

                    hostname_block = rsoup.find(
                        'td', headers='offline-device-host-name')
                    name = rsoup.find(
                        'a', class_='label device-name private').text.replace('\r', '').replace('\t', '')
                    res_type = 'dhcp' if 'DHCP' in rsoup.find(
                        'td', headers='offline-device-dhcp-reserve').text.upper() else 'static'
                    network = rsoup.find(
                        'td', headers='offline-device-conncection').text.replace(' ', '')

                    ipv4_address = 'Unknown'
                    ipv6_address = 'Unknown'
                    mac_address = 'Unknown'

                    # advanced info
                    adv_info = hostname_block.find('div')
                    for child in adv_info.find_all('dd'):

                        if 'ipvaddloc' in str(child):
                            ipv4_address = str(child.next_sibling)
                        if 'ipv6addloc' in str(child):
                            ipv6_address = str(child.next_sibling)
                        if 'macaddlocnew' in str(child):
                            mac_address = str(child.next_sibling)

                    devices['offline'].append({
                        'name': name,
                        'lease_type': res_type,
                        'network': network,
                        'ipv4': ipv4_address,
                        'ipv6': ipv6_address,
                        'mac': mac_address,
                    })
                except Exception as e:
                    continue

        except Exception as e:
            print('Error gathering devices: {}'.format(str(e)))
            return {}
        return devices

    def online_devices(self) -> list:
        return self.devices()['online']

    def offline_devices(self) -> list:
        return self.devices()['offline']

    def connection_status(self) -> dict:
        status = {
            'lan': {},
            'wan': {},
            '2.4': {},
            '5.0': {},
        }

        if not self.has_session():
            print("You need to authenticate first!")
            return {}

        headers = {
            'Host': self.host,
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Referer': 'http://{}'.format(self.host),
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
            'Cookie': self.session_cookie,
        }

        try:
            url = 'http://{}/connection_status.jst'.format(self.host)
            r = self.sess.get(url, headers=headers)

            soup = BeautifulSoup(str(r.content.decode()), 'html.parser')

            # LAN Status
            lan_status = soup.find(
                'div', class_='module forms block localIPNetwork')
            for element in lan_status.find_all('div', class_='form-row'):
                key = element.find('span', class_='readonlyLabel').text.strip()
                value = cleanval(element.find('span', class_='value').text)

                if 'ipaddloc' in str(element):
                    status['lan']['ipv4_address'] = value
                elif 'subnetloc' in str(element):
                    status['lan']['subnet_mask'] = value
                elif 'dhcpserverloc' in str(element):
                    status['lan']['dhcp_server_status'] = value
                elif 'dhcplease' in str(element):
                    status['lan']['dhcp_lease'] = value
                elif 'linklocalloc' in str(element):
                    status['lan']['link_local_address'] = value
                elif 'globalgateway' in str(element):
                    status['lan']['global_gateway_address'] = value
                elif 'deprev6' in str(element):
                    status['lan']['delegated_prefix'] = value
                elif 'ipv6dns' in str(element):
                    status['lan']['ipv6_dns'] = value
                elif 'noclients' in str(element):
                    status['lan']['connected_device_count'] = value

            # WAN Status
            wan_block = soup.find('h2', id='wannet').parent
            for element in wan_block.find_all('div', class_='form-row'):
                value = cleanval(element.find('span', class_='value').text)

                if 'wannetstat' in str(element):
                    status['wan']['wan_network_status'] = value
                elif 'wanip4' in str(element):
                    status['wan']['ipv4_address'] = value
                elif 'wanip6' in str(element):
                    status['wan']['ipv6_address'] = value

            # Wireless Network Status
            lanwi = soup.find_all(
                'div', class_='module forms block private-wifi')
            for block in lanwi:
                # WiFi 2.4 Status
                if 'Wi-Fi 2.4 GHz' in str(block):
                    for row in block.find_all('div', class_='form-row'):
                        value = cleanval(row.find('span', class_='value').text)

                        if 'wifinet24' in str(row):
                            status['2.4']['status'] = value
                        elif 'supprot' in str(row):
                            status['2.4']['supported_protocols'] = value.split(
                                ',')
                        elif 'secloc' in str(row):
                            status['2.4']['security'] = value
                        elif 'noclients' in str(row):
                            status['2.4']['connected_devices'] = value

                # WiFi 5G Status
                elif 'Wi-Fi 5 GHz' in str(block):
                    for row in block.find_all('div', class_='form-row'):
                        value = cleanval(row.find('span', class_='value').text)

                        if 'wifinet5ghz' in str(row):
                            status['5.0']['status'] = value
                        elif 'supprot' in str(row):
                            status['5.0']['supported_protocols'] = value.split(
                                ',')
                        elif 'secloc' in str(row):
                            status['5.0']['security'] = value
                        elif 'noclients' in str(row):
                            status['5.0']['connected_devices'] = value

        except Exception as e:
            print('Error parsing status: {}'.format(e))

        return status
