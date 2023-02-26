import json
import uuid
import urllib
import urllib3
import requests
from requests import session
from bs4 import BeautifulSoup
from colorama import Fore


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


class Device():
    def __init__(self, name: str, connected: bool, network: str, lease_type: str, ipv4: str, ipv6: str, mac: str):
        self.name: str = name
        self.connected: bool = connected
        self.network: str = network
        self.lease_type: str = lease_type
        self.ipv4: str = ipv4
        self.ipv6: str = ipv6
        self.mac: str = mac

    def pretty(self) -> str:
        device_pretty = """
[Device: {c3}{_1}{r} | Connected: {cc}{_2}{r}]
 {c1}Network:{c2} {_3}{r}
 {c1}Lease Type:{c2} {_4}{r}
 {c1}IPv4:{c2} {_5}{r}
 {c1}IPv6:{c2} {_6}{r}
 {c1}MAC:{c2} {_7}{r}""".format(
            c1=Fore.CYAN,
            c2=Fore.LIGHTYELLOW_EX,
            c3=Fore.LIGHTBLUE_EX,
            r=Fore.RESET,
            cc=Fore.GREEN if self.connected else Fore.RED,


            _1=self.name,
            _2='Yes' if self.connected else 'No',
            _3=self.network,
            _4=self.lease_type.upper() if self.lease_type == 'dhcp' else self.lease_type.title(),
            _5=self.ipv4,
            _6=self.ipv6,
            _7=self.mac,)
        return device_pretty


class Gateway:
    """
    """

    def __init__(self, host: str = '192.168.0.1', verbose: bool = False, use_https: bool = False):
        self.host = host
        self.verbose = verbose
        self.use_https = use_https

        if use_https:
            self.full_host = 'https://{}'.format(self.host)
        else:
            self.full_host = 'http://{}'.format(self.host)

        self.session_cookie = None
        self.sess = requests.session()

        self.GET_headers = {
            'Host': self.host,
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Referer': self.full_host,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
            'Cookie': self.session_cookie,
        }

    def has_session(self) -> bool:
        return True if self.session_cookie != None else False

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticated with the gatewat using given credentials

        :param username: Username to authenticate with
        :param password: Password to authenticate with
        """
        logged_in = False
        session_cookie = None
        data = ''

        url_enc_data = 'username={}&password={}&locale=false'.format(
            username, password)

        headers = {
            'Host': self.host,
            'Content-Length': str(len(url_enc_data)),
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Origin': self.full_host,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Referer': self.full_host,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }

        params = {
            'username': username,
            'password': password,
            'locale': False,
        }

        if self.verbose:
            print(' Authenticating with {} as {}'.format(self.host, username))

        url = '{}/check.jst'.format(self.full_host)
        try:
            r = self.sess.post(url, headers=headers, data=params)
            data = r.content.decode()
            if 'Set-Cookie' in list(r.headers.keys()):
                session_cookie = r.headers.get('Set-Cookie')
                logged_in = True
        except Exception as e:
            print("Error logging in: {}".format(str(e)))
        self.session_cookie = session_cookie

        if self.verbose:
            if logged_in:
                print(' Logged in')
            else:
                print(' Authentication failed')
                print(' Server Response:\n{}'.format(data))
        return logged_in

    def devices(self) -> list[Device]:
        """
        Returns a list of devices known by the gateway as python objects
        """
        odevices = []
        url = '{}/connected_devices_computers.jst'.format(self.full_host)

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return []

        try:
            r = self.sess.get(url, headers=self.GET_headers)

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

                    odevices.append(Device(
                        name=name,
                        connected=True,
                        network=network,
                        lease_type=res_type,
                        ipv4=ipv4_address,
                        ipv6=ipv6_address,
                        mac=mac_address))
                except Exception as e:
                    if self.verbose:
                        print(
                            ' A non-fatal exception occured while parsing a device: {}'.format(str(e)))
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

                    odevices.append(Device(
                        name=name,
                        connected=False,
                        network=network,
                        lease_type=res_type,
                        ipv4=ipv4_address,
                        ipv6=ipv6_address,
                        mac=mac_address))
                except Exception as e:
                    if self.verbose:
                        print(
                            ' A non-fatal exception occured while parsing a device: {}'.format(str(e)))
                    continue
        except Exception as e:
            print(' Error gathering devices: {}'.format(str(e)))
        return odevices

    def online_devices(self) -> list[Device]:
        """
        Returns known and online devices as python objects
        """
        return [d for d in self.devices() if d.connected]

    def offline_devices(self) -> list[Device]:
        """
        Returns known and online devices as python objects
        """
        return [d for d in self.devices() if not d.connected]

    def connection_status(self) -> dict:
        """
        Returns connection status information
        """
        status = {
            'lan': {},
            'wan': {},
            '2.4': {},
            '5.0': {},
        }

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return status

        try:
            url = '{}/connection_status.jst'.format(self.full_host)
            r = self.sess.get(url, headers=self.GET_headers)

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

    def wifi_credentials(self) -> dict:
        """
        Retrieve Wi-Fi Credentials for 2G and 5G networks.

        """
        creds = {
            '2.4G': {

            },
            '5G': {

            }
        }

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return creds

        try:
            url = '{}/at_a_glance.jst'.format(self.full_host)
            r = self.sess.get(url, headers=self.GET_headers)

            soup = BeautifulSoup(str(r.content.decode()), 'html.parser')

            creds['2.4G']['ssid'] = soup.find(
                'span', id='wifissid24').find_next('span').text
            creds['2.4G']['password'] = soup.find(
                'span', id='wifipasskey24').find_next('span').text
            creds['5G']['ssid'] = soup.find(
                'span', id='wifissid5').find_next('span').text
            creds['5G']['password'] = soup.find(
                'span', id='wifipasskey5').find_next('span').text

        except Exception as e:
            print(e)
        return creds

    def credentials(self, network: str = '2.4') -> tuple:
        creds = (None, None)
        if '2' in network or network == '2.4':
            creds[0] = self.wifi_credentials()['2.4G']['ssid']
            creds[1] = self.wifi_credentials()['2.4G']['password']
        elif '5' in network:
            creds[0] = self.wifi_credentials()['5G']['ssid']
            creds[1] = self.wifi_credentials()['5G']['password']
        return creds

    def software_version(self) -> dict:
        """
        Return router software version
        """
        version_info = {
            'note': 'the web developer left notes calling their code a mess, dont blame me here.'
        }

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return {}

        url = '{}/software.jst'.format(self.full_host)
        try:
            r = self.sess.get(url, headers=self.GET_headers)
            soup = BeautifulSoup(str(r.content.decode()), 'html.parser')

            block = soup.find('div', class_='module forms')
            for element in block.find_all('div', class_='form-row'):
                value = cleanval(element.find('span', class_='value').text)

                if 'Software Version:' in str(element):
                    version_info['etma_docsis_version'] = value
                elif 'Software Image Name:' in str(element):
                    version_info['software_image_name'] = value
                elif 'Advanced Services:' in str(element):
                    version_info['advanced_services'] = value
        except Exception as e:
            print('Error while parsing version info: {}'.format(str(e)))
        return version_info

    def network_setup(self) -> dict:
        setup_conf = {}

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return setup_conf

        url = '{}/network_setup.jst'.format(self.full_host)
        try:
            r = self.sess.get(url, headers=self.GET_headers)
            soup = BeautifulSoup(str(r.content.decode()), 'html.parser')

            for row in soup.find_all('div', class_='form-row'):
                value = cleanval(row.find('span', class_='value').text)

                if 'Internet:' in str(row):
                    setup_conf['internet_active'] = value

                elif 'Local time:' in str(row):
                    setup_conf['local_time'] = value

                elif 'System Uptime:' in str(row):
                    setup_conf['uptime'] = value

                elif 'WAN IP Address (IPv4):' in str(row):
                    setup_conf['wan_ipv4'] = value

                elif 'WAN Default Gateway Address (IPv4):' in str(row):
                    setup_conf['wan_default_ipv4'] = value

                elif 'WAN IP Address (IPv6):' in str(row):
                    setup_conf['wan_ipv6'] = value

                elif 'WAN Default Gateway Address (IPv6):' in str(row):
                    setup_conf['wan_default_ipv6'] = value

                elif 'Delegated prefix (IPv6):' in str(row):
                    setup_conf['delegated_ipv6_prefix'] = value

                elif 'Primary DNS Server (IPv4):' in str(row):
                    setup_conf['primary_ipv4_dns_server'] = value

                elif 'Secondary DNS Server (IPv4):' in str(row):
                    setup_conf['secondary_ipv4_dns_server'] = value

                elif 'Primary DNS Server (IPv6):' in str(row):
                    setup_conf['primary_ipv6_dns_server'] = value

                elif 'Secondary DNS Server (IPv6):' in str(row):
                    setup_conf['secondary_ipv6_dns_server'] = value

        except Exception as e:
            print('Error parsing network setup: {}'.format(str(e)))
        return setup_conf

    def filter_host(self, mac: str, name: str = str(uuid.uuid4()), action: int = 0, ssid: int = 1) -> bool:
        """
        Allow/Block connections from a device by it's MAC address.

        :param mac: MAC address of the device
        :param action: Action to take when a device with this MAC
                       address connects to the router.
                       Options:
                        0 - deny
                        1 - allow
        :param ssid: Wireless network this rule applies to.
                     Options:
                     1 - 2.4GHz Network
                     2 - 5GHz Network
        """
        success = False
        filter_mode = 'deny' if action == 0 else 'allow'

        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return False

        data = {
            "configInfo": "{\"ssid_number\":\"" + str(ssid) + "\",\"filtering_mode\":\"" + filter_mode + "\",\"ft\":[[\"" + name + "\",\"" + mac + "\"]],\"target\":\"save_filter\"}"
        }

        headers = {
            'Host': self.host,
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Origin': self.full_host,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': '*/*',
            'Referer': '{}/wireless_network_configuration.jst'.format(self.full_host),
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
            'Cookie': self.session_cookie,
        }
        url = '{}/actionHandler/ajaxSet_wireless_network_configuration.jst'.format(
            self.full_host)
        try:
            r = self.sess.post(url, headers=headers, data=data)
            # print(r.content.decode())
            if int(r.status_code) == 200:
                success = True
        except Exception as e:
            print('Error filtering host: {}'.format(str(e)))
        return success

    def block_device(self, mac: str, network: int) -> None:
        """
        Blocks access to the network for a single device by its
        MAC address.

        :param mac: MAC address of the device.
        :param ssid: Wireless network this rule applies to.
                     Options:
                     1 - 2.4GHz Network
                     2 - 5GHz Network
        """
        self.filter_host(mac, action=0, ssid=network)

    def unblock_device(self, mac: str, network: int) -> None:
        """
        Unblocks access to the network for a single device by its
        MAC address.

        :param mac: MAC address of the device.
        :param ssid: Wireless network this rule applies to.
                     Options:
                     1 - 2.4GHz Network
                     2 - 5GHz Network
        """
        self.filter_host(mac, action=1, ssid=network)

    def query_device(self, ipv4=None, ipv6=None, mac=None, name=None, part_name=None) -> Device:
        """
        Get a python object representation of a device by its name, ipv4 address, 
        ipv6 address, or mac address. Only use one at a time, not all values are always
        filled. 

        :param ipv4: Search a device by its ipv4
        :param ipv6: Search a device by its ipv6
        :param mac: Search a device by its mac
        :param name: Search a device by its name
        :param part_name: Search a device by a substring in its name.
                          will return the first device with a name containing
                          this substring. (not case sensitive.)
        """
        
        # dev = None
        if not self.has_session():
            print(" You are unauthorized, start by authenticating.")
            return dev

        q_key = ''
        value = None
        

        devices = self.devices()

        for d in devices:
            if ipv4:
                if d.ipv4 == ipv4:
                    dev = d
                    break
            elif ipv6:
                if d.ipv6 == ipv6:
                    dev = d
                    break
            elif name:
                if d.name == ipv6:
                    dev = d
                    break
            elif mac:
                if d.mac == mac:
                    dev = d
                    break
            elif part_name:
                if part_name.lower() in d.name.lower():
                    dev = d
                    break

        return dev

    def logout(self) -> bool:
        if self.verbose:
            print(' Logging Out')
        logged_out = False
        r = self.sess.get(
            '{}/home_loggedout.jst'.format(self.full_host), headers=self.GET_headers)
        logged_out = True if int(r.status_code) == 302 else False
        return logged_out
