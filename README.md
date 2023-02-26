# CGM4140COM_SDK
Python SDK for Xfinity Broadcoam Router CGM4140COM (used by multiple ISPs, made for Cox)


# Installation

Download the respository into a folder, then change into it.
```
sudo git clone https://github.com/CyberJosie/CGM4140COM_SDK /opt
cd CGM4140COM_SDK
```

Install dependencies.
```
sudo apt-get install python3 python3-pip
python3 -m pip install -r requirements.txt
```

Create symlinks.
```
sudo ln -s /opt/CGM4140COM_SDK/gatewayclitool.sh /usr/local/bin/gwcli
```

# Usage Examples

This tool interacts with the gateway via its web server. Each time the tool is ran a session is opened, authenticated, some requests are made and then the session is logged out. This means you must specify the credentials in every command. You can do this either via the `--username` and `--password` switches or by the `--auth-file` switch. 

## Connection Status
```
gwcli --auth-file creds.txt --conn-status
# Or
gwcli -a creds.txt -cs
```

## Network Setup Information
This is basically advanced connection status.
```
gwcli --auth-file creds.txt --net-setup
# Or
gwcli -a creds.txt -ns
```

## List Devices
```
gwcli --auth-file creds.txt --list-devices
# Or
gwcli -a creds.txt -ld
```

## List Connected Devices
```
gwcli --auth-file creds.txt --connected
# Or
gwcli -a creds.txt -cd
```

## List Disconnected Devices
```
gwcli --auth-file creds.txt --disconnected
# Or
gwcli -a creds.txt -dd
```

## Search Device
```
# Search by a part of the name
gwcli -a creds.txt --query part_name=phone
# Search by the ip address
gwcli -a creds.txt --query ipv4=192.168.0.77
# Search by the mac address
gwcli -a creds.txt --query mac=XX:XX:XX:XX:XX:XX
```