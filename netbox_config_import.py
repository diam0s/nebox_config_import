# Netbox_config_import
#
# Copyright (C) 2020 Dmitriy Ageyev
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import argparse
import logging
import operator
import re
import urllib.error
import urllib.request
from functools import reduce
from netaddr import IPAddress, IPNetwork
from netbox import NetBox
from termcolor import colored

def interface_log_enter(func):
    def wrapper(*args, **kwargs):
        global output
        if isinstance(args[0], str):
            update_status = output.update_position(args[0])
        if isinstance(args[0], int):
            update_status = output.update_position('Vlan %s' % args[0])
        if isinstance(args[0], dict):
            upd = args[0].get('ifname') or 'Vlan %s' % args[0].get('vid')
            update_status = output.update_position(upd)
        result = func(*args, **kwargs)
        if update_status:
            output.escape()
        return result
    return wrapper

class LogDict(dict):
    position = None
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value
    def __get_position__(self, dict_map):
        if self.position and dict_map:
            if set(dict_map).intersection(self.position) == set(dict_map):
                return dict_map
            if isinstance(dict_map, str):
                dict_map = self.position + [dict_map]
            elif isinstance(dict_map, list):
                dict_map = self.position + dict_map
        else:
            dict_map = self.position
        if not dict_map:
            print("No position set")
            return None
        return dict_map
    def get_from_dict(self, dict_map=None):
        dict_map = self.__get_position__(dict_map)
        return reduce(operator.getitem, dict_map, self)
    def set_in_dict(self, value, dict_map=None):
        dict_map = self.__get_position__(dict_map)
        item = self.get_from_dict(dict_map)
        for line in value.splitlines():
            if item['msg']:
                item['msg'] += [line]
            else:
                item['msg'] = [line]
    def set_position(self, dict_map):
        if isinstance(dict_map, str):
            self.position = [dict_map]
        elif isinstance(dict_map, list):
            self.position = dict_map
        else:
            return None
        return True
    def update_position(self, dict_map):
        if isinstance(dict_map, str):
            if dict_map in self.position:
                return None
            self.position += [dict_map]
        elif isinstance(dict_map, list):
            if set(self.position).intersection(dict_map) == set(dict_map):
                return None
            self.position += dict_map
        return True
    def escape(self, depth=1):
        self.position = self.position[:len(self.position)-depth]
    def clear_position(self):
        self.position = None

CONFIG_SRV = 'http://10.10.10.10/node/fetch/'
NETBOX = 'netbox.core.myoffice.nz'
netbox_auth_token = 'zzzzzzzzzzzzzzzzzzzzzzzzzz'
netbox = NetBox(host=NETBOX, ssl_verify=True, use_ssl=True, auth_token=netbox_auth_token)

def color_line(line):
    if 'Error' in line:
        return colored(line, 'red')
    if 'Warning' in line:
        return colored(line, 'yellow')
    return colored(line, 'green')

def print_output(log, *, indent=0):
    out = ''
    if isinstance(log, dict):
        for index, value in log.items():
            if index == 'msg':
                for item in value:
                    out += ' ' * indent + color_line(item) + '\n'
            else:
                out += ' ' * indent + index + '\n'
                out += print_output(value, indent=indent + 4)
    else:
        assert False, type(log)
    return out

def print_log(msg, pos=None):
    global output
    if pos:
        output.set_in_dict(msg, pos)
    else:
        output.set_in_dict(msg)

def get_url(link):
    try:
        with urllib.request.urlopen(link) as response:
            myfile = response.read()
    except urllib.error.URLError as e:
        print(e)
        return None
    return myfile.decode("utf-8")

def parse_cisco_conf(conf):
    re_vid = re.compile(r'^\s*interface Vlan(?P<vid>\d+)\n')
    re_interface = re.compile(r'^\s*interface (?P<interface>(Loopback|FastEthernet|GigabitEthernet|TenGigabitEthernet)[0-9/]+)\n')
    re_desc = re.compile(r'\s*description (?P<desc>(.*)+)\n')
    re_ipv4 = re.compile(r'\s*ip address (?P<address>[0-9.]+) (?P<netmask>[0-9.]+)\n')
    re_ipv6 = re.compile(r'\s*ipv6 address (?P<address>[0-9A-Fa-f:/]+)\n')
    re_vlist = re.compile(r'\s*switchport trunk allowed vlan (?P<vlist>[0-9\-\,]+)\n')
    re_ac_vlan = re.compile(r'\s*switchport access vlan (?P<ac_vlan>\d+)\n')
    re_status = re.compile(r'\s*shutdown\s*\n')
    my_config = []
    blocks = conf.split('!')
    for block in blocks:
        if not 'interface ' in block:
            continue
        i = {'ip_list': []}
        if re_vid.match(block):
            i['type'] = 'vlan'
            i['vid'] = int(re_vid.match(block)['vid'])
            i['ifname'] = 'Vlan ' + re_vid.match(block)['vid']
        elif re_interface.match(block):
            i['type'] = 'ethernet'
            i['ifname'] = re_interface.match(block)['interface']
            i['vlist'] = []
            if re_ac_vlan.search(block):
                i['vlist'] = [int(re_ac_vlan.search(block)['ac_vlan'])]
            elif re_vlist.search(block):
                vl = re_vlist.search(block)['vlist'].split(',')
                for v in vl:
                    if '-' in v:
                        v = v.split('-')
                        i['vlist'].extend(range(int(v[0]), int(v[1])+1))
                    else:
                        i['vlist'].append(int(v))
        else:
            continue
        if re_desc.search(block):
            desc = re.sub(r'[\"\']', '', re_desc.search(block)['desc'])
            i['description'] = desc
        for ip in re_ipv4.findall(block):
            cidr = IPAddress(ip[1]).netmask_bits()
            ip = ip[0] + '/' + str(cidr)
            i['ip_list'].append(ip)
        for ip in re_ipv6.findall(block):
            i['ip_list'].append(ip)
        if re_status.search(block):
            i['status'] = 'Deprecated'
        else:
            i['status'] = "Active"
        my_config.append(i)
    return my_config

def parse_mikrotik_line(itype, item):
    i = {
        'type': itype,
        'ifname': item['ifname'],
        'description': '',
        'ip_list': []
    }
    if item['description']:
        i['description'] = re.sub(r'[\"\']', '', item['description'])
    if item['status'] == 'yes':
        i['status'] = 'Deprecated'
    else:
        i['status'] = 'Active'
    if itype == 'ethernet':
        i['name'] = item['name']
        i['vlist'] = []
    if itype == 'vlan':
        i['iface'] = item['iface']
        i['vid'] = int(item['vid'])
    return i

def split_mikrotik_conf(conf):
    re_block = re.compile(r'^\s*\/(?P<name>[\w\ \-]+)\s*$')
    chunks = re.split(r'(\s*\n\/[\w\ \-]+\s*\n)', conf)
    cfg = {}
    for chunk in enumerate(chunks):
        chunk_name = re_block.match(chunk[1])
        if chunk_name:
            cfg[chunk_name['name']] = chunks[chunk[0]+1]
    return cfg

def parse_mikrotik_conf(conf):
    conf = split_mikrotik_conf(conf)
    re_ethernet = re.compile(r'\s*set[\w\[\ \-]+\=(?P<ifname>ether\d+)\s*\]\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(name=(?P<name>[\w\.\-]+))?\s*')
    re_vlan = re.compile(r'\s*add\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(interface=(?P<iface>[\w\.\-]+))\s*(name=(?P<ifname>[\w\.\-]+))?\s*(vlan-id=(?P<vid>\w+))\s*')
    re_gre = re.compile(r'\s*add\s*(\!\w+)?\s*([\w\-]+\=[\d\.]+)?\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(name=(?P<ifname>[\w\.\-]+))?\s*')
    re_bridge = re.compile(r'\s*add\s*(arp=\w+)?\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(fast-forward=\w+)?\s*(name=(?P<ifname>[\w\.\-]+))\s*')
    re_ip = re.compile(r'\s*add\s*(address=(?P<address>[\d\.]+\/[\d]+))?\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(interface=(?P<iface>[\w\.\-]+))?\s*')
    re_bp = re.compile(r'\s*add\s*(bridge=(?P<br>[\w\-\.]+))\s*(comment=(?P<description>(\"[\w\&\ \.\(\)\#\-\/]+\"|\w+)))?\s*(disabled=(?P<status>\w+))?\s*(hw=\w+)?\s*(interface=(?P<iface>[\w\.\-]+))\s*')
    type_list = ['bridge', 'ethernet', 'vlan', 'gre']
    my_config = []
    for itype in type_list:
        conf_lines = conf['interface ' + itype].splitlines()
        for line in conf_lines:
            re_item = locals()['re_' + itype].search(line)
            if re_item:
                i = parse_mikrotik_line(itype, re_item)
                my_config.append(i)
    bp_block = conf['interface bridge port'].splitlines()
    for line in bp_block:
        bp_item = re_bp.search(line)
        if bp_item:
            bp_vlan = int(bp_item['br'][bp_item['br'].rfind(".")+1:])
            list(interface['vlist'].append(bp_vlan) for interface in my_config if interface["ifname"] == bp_item['iface'] and interface['type'] == 'ethernet')
    ip_block = conf['ip address'].splitlines()
    for line in ip_block:
        for ip in re_ip.findall(line):
            ip_addr = None
            ip_iface = None
            for i in ip:
                ip_re = re.search(r'address=([\d.\/]+)', i)
                if ip_re:
                    ip_addr = ip_re.group(1)
                iface_re = re.search(r'interface=([\w.\-]+)', i)
                if iface_re:
                    ip_iface = iface_re.group(1)
            list(interface['ip_list'].append(ip_addr) for interface in my_config if interface["ifname"] == ip_iface)
    # iterate by vlans in $my_config and add vlan to iface if iface in vlan['iface']
    for vlan in my_config:
        if vlan['type'] == 'vlan':
            list(interface['vlist'].append(int(vlan['vid'])) for interface in my_config if interface["ifname"] == vlan['iface'] and interface['type'] == 'ethernet')
    return my_config

@interface_log_enter
def get_netbox_vlan(vid):
    obj = netbox.ipam.get_vlans(vid=vid)
    if not obj:
        print_log('Error! No such vlan listed in NetBox')
        return None
    if len(obj) > 1:
        print_log('Error! Vlan duplicate was found in NetBox.')
        return None
    obj = obj[0]
    vlan = {
        'id':obj['id'],
        'vid': obj['vid'],
        'last_updated': obj['last_updated'],
        'status': obj['status']['label'],
        'description': obj['name'],
        'comment': obj['description'],
        'ifname': 'Vlan %s' % obj['vid'],
        'prefixes': []
    }
    prefixes = netbox.ipam.get_ip_prefixes(vlan_vid=vid)
    if not prefixes:
        print_log('Warning! No prefixes assigned for vlan')
    for prefix in prefixes:
        vlan['prefixes'].append({
            'prefix': prefix['prefix'],
            'last_updated': prefix['last_updated'],
            'description': prefix['description'],
            'status': prefix['status']['label']
            })
    return vlan

@interface_log_enter
def get_netbox_interface(ifname, device):
    if_dict = {'FastEthernet': 'fa', 'GigabitEthernet': 'gi', 'TenGigabitEthernet': 'te', 'ether': 'eth'}
    re_int = re.compile(r'(?P<name>[A-Za-z\ \-]+)(?P<id>[\d\/\-]+)')
    alt_ifname = if_dict.get(re_int.match(ifname)['name']) + re_int.match(ifname)['id']
    obj = netbox.dcim.get_interfaces(device=device, name=ifname) or netbox.dcim.get_interfaces(device=device, name=alt_ifname)
    if not obj:
        return None
    if len(obj) > 1:
        print_log('Error! Interface duplicate was found in NetBox.')
        return None
    obj = obj[0]
    iface = {
        'id':obj['id'],
        'ifname': obj['name'],
        'description': obj['description'],
        'ip_list': []
    }
    if obj['enabled']:
        iface['status'] = 'Active'
    else:
        iface['status'] = 'Deprecated'
    addresses = netbox.ipam.get_ip_addresses(interface_id=obj['id'])
    if not addresses:
        return iface
    for address in addresses:
        iface['ip_list'].append({
            'address': address['address'],
            'last_updated': address['last_updated'],
            'description': address['description'],
            'status': address['status']['label']
            })
    return iface

@interface_log_enter
def get_netbox_ip_address(addr):
    obj = netbox.ipam.get_ip_addresses(address=addr)
    if not obj:
        print_log('Error! No such address listed in Netbox')
        return None
    if len(obj) > 1:
        print_log('Error! Address duplicate was found in NetBox')
        return None
    obj = obj[0]
    ip_addr = {
        'address': obj['address'],
        'last_updated': obj['last_updated'],
        'iface': obj['interface'],
        'status': obj['status']['label'],
        'description': obj['description']
    }
    return ip_addr

def string_similarity_check(a, b):
    min_len = len(min((a.split(' '), b.split(' ')), key=len))
    a = a.split(' ')
    b = b.replace(' ', '')
    count = 0
    for i in a:
        if i in b:
            count += 1
    if count <= min_len/2:
        return False
    return True

def compare_description(desc_c, desc_nb):
    func = lambda x: re.sub(r'[^\w\ \.\-]+', ' ', x).lower()
    if not desc_c:
        print_log('Error! Discription on the device is missing! Netbox description: %s' % desc_nb)
    elif not desc_nb:
        print_log('Error! Discription in the Netbox is missing! Device description: %s' % desc_c)
    elif func(desc_c) == func(desc_nb):
        return True
    elif string_similarity_check(func(desc_c), func(desc_nb)):
        return True
    else:
        print_log('Error! Discription mismatch!\nDevice description: %s; Netbox description %s' % (desc_c, desc_nb))
    return True

@interface_log_enter
def check_interface(iface, nb_if):
    if not nb_if:
        if iface['status'] == 'Active':
            print_log("Error! No interface in the Netbox")
            for ip in iface['ip_list']:
                check_ip(ip, iface)
            if iface.get('vlist'):
                for vid in iface['vlist']:
                    nb_v = get_netbox_vlan(vid)
                    check_interface(iface, nb_v)
        return None
    if iface['status'] != nb_if['status']:
        print_log('Error! Status mismatch.\nStatus on interface: %s; In Netbox %s' % (iface['status'], nb_if['status']))
    #skip if compare discription on trunk interface with description on vlan
    if not iface.get('vid') and nb_if.get('vid') and len(iface['vlist']) > 1:
        return True
    compare_description(iface.get('description'), nb_if['description'])
    return True

@interface_log_enter
def check_ip(ip, iface, iface_id=None):
    nb_ip = get_netbox_ip_address(ip)
    if not nb_ip:
        if iface['status'] == 'Active' and (FORCE or get_approval('Add IP %s to NetBox' % (ip))):
            out = create_netbox_ip(ip, iface['description'], iface_id)
            if out:
                print_log('IP was added to Netbox')
            else:
                print_log("Couldn't add new IP to Netbox")
        return None
    if iface['status'] == 'Deprecated' and nb_ip['status'] == 'Active':
        print_log('Error! Status mismatch.\nStatus on interface: %s; on IP in Netbox: %s' % (iface['status'], nb_ip['status']))
    compare_description(iface.get('description'), nb_ip['description'])
    return True

@interface_log_enter
def check_vlan_prefixes(nb_v, ip_list):
    re_ip = re.compile(r'(?P<address>[A-Fa-f\d\.\:]+)\/(?P<cidr>\d+)')
    ips_in_prefixes = []
    for vlan_prefix in nb_v['prefixes']:
        ip_in_prefix = list(ip for ip in ip_list if IPAddress(re_ip.match(ip)['address']) in IPNetwork(vlan_prefix['prefix']))
        ips_in_prefixes = list(set(ips_in_prefixes + ip_in_prefix))
        for ip in ip_in_prefix:
            output.update_position('Prefix %s' % ip)
            if vlan_prefix['status'] != nb_v['status']:
                print_log('Error! Status mismatch.\nStatus on vlan %s: %s; on prefix: %s' % (nb_v['vid'], nb_v['status'], vlan_prefix['status']))
            compare_description(nb_v['description'], vlan_prefix['description'])
            output.escape()
    return ips_in_prefixes

@interface_log_enter
def create_netbox_interface(iface, device):
    dev_id = netbox.dcim.get_devices(name=device)[0]['id']
    if_dict = {'FastEthernet': 'fa', 'GigabitEthernet': 'gi', 'TenGigabitEthernet': 'te', 'ether': 'eth'}
    re_int = re.match(r'(?P<name>[A-Za-z\ \-]+)(?P<id>[\d\/\-]+)', iface['ifname'])
    alt_ifname = if_dict.get(re_int['name']) + re_int['id']
    bw_dict = {'FastEthernet': 800, 'GigabitEthernet': 1000, 'TenGigabitEthernet': 1310, 'ether': 800}
    vid_list = []
    for vlan in iface.get('vlist'):
        vlan_id = netbox.ipam.get_vlans(vid=vlan)[0]['id']
        vid_list.append(vlan_id)
    out1 = netbox.dcim.create_interface(device_id=dev_id, name=alt_ifname, form_factor=bw_dict.get(re_int['name']), description=iface['description'], tagged_vlans=vid_list)
    if out1.get('id'):
        for ip in iface["ip_list"]:
            output.update_position(ip)
            out2 = update_netbox_ip(ip, out1['id'])
            if not out2 and (FORCE or get_approval('\nCreate ip %s description: %s in the NetBox' % (ip, iface["description"]))):
                out3 = create_netbox_ip(ip, iface["description"], out1['id'])
                if not out3:
                    print_log("Couldn't create IP")
            else:
                print_log("IP updated")
            output.escape()
        return out1
    else:
        return None

@interface_log_enter
def create_netbox_ip(ip, desc, iface_id=None):
    out = netbox.ipam.create_ip_address(address=ip, description=desc, interface=iface_id)
    return out

@interface_log_enter
def create_netbox_vlan(iface):
    out1 = netbox.ipam.create_vlan(vlan_name=iface['description'], vid=iface['vid'])
    if not out1.get('id'):
        return None
    for ip in iface['ip_list']:    # no prefix_list. has ip list # probably check IP
        prefix = str(IPNetwork(ip).cidr)
        output.update_position('Prefix %s' % prefix)
        out2 = update_netbox_prefix(prefix, out1['id'])
        if not out2 and (FORCE or get_approval('\nCreate prefix %s description: %s in the NetBox' % (prefix, iface['description']))):
            out3 = create_netbox_prefix(prefix, iface['description'], out1['id'])
            if not out3:
                print_log("Couldn't create prefix")
        else:
            print_log("Prefix updated")
        output.escape()
    return out1

def create_netbox_prefix(prefix, desc, vlan_nb_id):
    out = netbox.ipam.create_ip_prefix(prefix=prefix, description=desc, vlan=vlan_nb_id)
    return out

def update_netbox_ip(addr, iface_id):
    ips = netbox.ipam.get_ip_addresses(address=addr)
    if len(ips) > 1:
        print_log("IP address duplicate was found")
    elif len(ips) == 1:
        out = netbox.ipam.update_ip(ip_address=addr, interface=iface_id)
        return out
    return None

def update_netbox_prefix(prefix, vlan_nb_id):
    prefixes = netbox.ipam.get_ip_prefixes(within_include=prefix)
    if len(prefixes) > 1:
        for pref in prefixes:
            if pref['prefix'] == prefix:
                out = netbox.ipam.update_ip_prefix(ip_prefix=prefix, vlan=vlan_nb_id)
    elif len(prefixes) == 1:
        out = netbox.ipam.update_ip_prefix(ip_prefix=prefix, vlan=vlan_nb_id)
    else:
        print_log("No prefix was found")
        return None
    print_log("Prefix was updated")
    return out

# For the future implementation
# def update_netbox_vlan()
# def update_netbox_interface()

def get_approval(question):
    reply = ''
    while len(reply) < 1:
        reply = str(input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'y' or reply[0] == 'yes':
        return True
    if reply[0] == 'n' or reply[0] == 'no':
        return False
    return get_approval("Uhhhh... please enter")

def match_device(my_config, device):
    for interface in my_config:
        output.set_position([device, interface['ifname']])
        if any('test' in x.lower() for x in (interface['ifname'], interface.get('description')) if isinstance(x, str)):
            print_log("Warning! Remove test interface")
            continue
        if interface['type'] == 'ethernet':
            nb_iface = get_netbox_interface(interface['ifname'], device)
            if not nb_iface:
                if interface['status'] == 'Active' and (FORCE or get_approval('\nCreate %s\nDescription: %s\nOn %s in the NetBox' % (interface['ifname'], interface['description'], device))):
                    nb_iface = create_netbox_interface(interface, device)
                    if nb_iface:
                        nb_iface = get_netbox_interface(interface['ifname'], device)
                        print_log('Interface was created on Netbox')
                    else:
                        print_log("Couldn't create the interface on Netbox")
            if not check_interface(interface, nb_iface):
                continue
            # compare ip lists
            match_set = set(interface['ip_list']).intersection(ip['address'] for ip in nb_iface['ip_list'] if ip['status'] == interface['status'])
            if len(interface['ip_list']) > len(match_set):
                diff1 = set(interface['ip_list']).difference(match_set)
                # probably get ip address from netbox
                for ip in diff1:
                    output.update_position(ip)
                    print_log("Warning! IP addresses is not assigned for the interface")
                    output.escape
                match_wo_status = set(interface['ip_list']).intersection(ip['address'] for ip in nb_iface['ip_list'])
                if len(match_wo_status) != len(match_set):
                    for ip in match_wo_status:
                        output.update_position(ip)
                        print_log("Error! Status mismatch for IP. Interface status: %s" % interface['status'])
                        output.escape
            if len(nb_iface['ip_list']) > len(match_set):
                # list with possible ip addresses on relevant vlan
                diff2 = set(ip['address'] for ip in nb_iface['ip_list']).difference(match_set)
                if not interface['vlist']:
                    # for each vlan in vlist check if ip from diff2 in vlan_prefix:
                    # create set with ips from vlan
                    ips_in_pref = []
                    for vlan in interface['vlist']:
                        output.update_position('Vlan %s' % vlan)
                        nb_vlan = get_netbox_vlan(vlan)
                        check_interface(interface, nb_vlan)
                        ips = check_vlan_prefixes(nb_vlan, diff2)
                        ips_in_pref = list(set(ips_in_pref + ips))
                        output.escape()
                    diff3 = set(diff2).difference(ips_in_pref)
                    # addresses from this list wasn't found in prefixes assigned for vlan
                    # getting ip from netbox, checking description, status
                    if diff3:
                        for ip in diff3:
                            output.update_position(ip)
                            print_log("Warning! Vlan IP in the configuration doesn't match netbox prefix.")
                            check_ip(ip, interface, nb_iface['id'])
                            output.escape()
                else:
                    print_log('Unknown IPs found: %s No vlans listed for the interface' % (diff2))
        elif interface['type'] == 'vlan':
            nb_iface = get_netbox_vlan(interface['vid'])
            if not nb_iface:
                if interface['status'] == 'Active' and (FORCE or get_approval('\nCreate %s\nDescription: %s in the NetBox' % ("Vlan " + interface['vid'], interface['description']))):
                    nb_iface = create_netbox_vlan(interface)
                    if nb_iface:
                        nb_iface = get_netbox_vlan(interface['vid'])
                        print_log('Vlan was created on Netbox')
                    else:
                        print_log("Couldn't create vlan on Netbox")
            if not check_interface(interface, nb_iface):
                continue
            ips_in_pref = check_vlan_prefixes(nb_iface, interface['ip_list'])
            diff = set(interface['ip_list']).difference(ips_in_pref)
            # addresses from this list wasn't found in prefixes assigned for vlan
            # getting ip from netbox, checking description, status
            if diff:
                for ip in diff:
                    output.update_position(ip)
                    print_log('Warning! Vlan IP: %s in the configuration not matches netbox prefix.' % ip)
                    check_ip(ip, interface, nb_iface['id'])
                    output.escape()
            # getting the list of interfaces which uses the vlan
            # if status down, raise warning
            int_uses_vlan = list(iface['ifname'] for iface in my_config if iface['type'] == 'ethernet' and iface.get('vlist') and interface['vid'] in iface['vlist'])
            if not int_uses_vlan:
                print_log("Vlan %s hasn't been used on any interface" % interface['vid'])
                # check if depricated ask to remove
            # else:
            #     print_log("Vlan %s used on interfaces %s on device %s" % (interface['vid'], int_uses_vlan, device))

logger = logging.getLogger('Netbox Config Import')
logging.basicConfig(level=logging.INFO)
# logging.basicConfig(filename='netbox_sync.log', filemode='a', level=logging.DEBUG,
    # format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

parser = argparse.ArgumentParser(description='Script to import your cisco/mikrotik configurations from config server into NetBox')
parser.add_argument('-f', '--force', action='store_true', help='Create IP and Interfaces without asking')
arguments = parser.parse_args()

FORCE = arguments.force

# make sure that config filenames == devices[name]
devices = [{'name': 'cisco_router_1', 'make': 'cisco'}, {'name': 'mikrotik.router.1', 'make': 'mikrotik'}]
output = LogDict()

for dev in devices:
    config = get_url(CONFIG_SRV + dev['name'])
    if dev['make'] == 'cisco':
        config = parse_cisco_conf(config)
    elif dev['make'] == 'mikrotik':
        config = parse_mikrotik_conf(config)
    print(dev['name'])
    match_device(config, dev['name'])
report = print_output(output)
print(report)
