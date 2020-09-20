#!/usr/bin/env python3
import os
import subprocess
import ipaddress
import json
import socket
from WgClient import WgClient

class WgServer(object):
    """Wireguard server class, holds wireguard clients and manages server configuration"""
    attribute_index = {
        'name' : 'Server name',
        'listen_port' : 'Listen port',
        'ip_address' : 'IP address',
        'network' : 'Network address',
        'config_dir' : 'Configuration directory',
        'private_key' : 'Private key',
        'public_key' : 'Public key',
        'server_config' : 'Server configuration',
        'interface_config' : 'Interface configuration',
        'netmask' : 'Network Mask',
        'wan_if' : 'WAN interface',
        'gateway' : 'Gateway mode [y/n]',
        'server_ip' : 'Server IP',
        'pre_up' : 'pre-up parameters',
        'post_up' : 'post-up parameters',
        'post_down' : 'post-down parameters',
        'allowed_ips' : 'Allowed networks',
        'dns_server' : 'Default client DNS server',
        'persistent_keepalive' : 'Default client persistent keepalive interval',
        'peers' : 'Wireguard clients',
        'ports' : 'Forwarded ports',
    }

    def __init__(
        self,
        name = None,
        interface_address = None,
        ip_address = None,
        network = None,
        netmask = None,
        listen_port = None,
        config_dir = None,
        wan_if = None,
        gateway = None,
        server_ip = None,
        debug = False,
        data_dump = None):
        """initialize the object"""
        self.debug = debug
        self.error = False
        if debug:
            print(f"Debugging enabled")
        if data_dump is None:
            self.read_from_file = False
            if interface_address is not None:
                try:
                    ip_interface = ipaddress.IPv4Interface(interface_address)
                    ip_network = ipaddress.IPv4Network(ip_interface.network)
                    ip_address = str(ip_interface.ip)
                    network = str(ip_interface.network)
                    netmask = str(ip_interface.netmask)
                    if ip_interface.ip not in ip_network.hosts():
                        print(f"IP '{ip_address}' is not in wireguard network '{network}'")
                        self.error = True
                except:
                    print("Invalid interface address specified")
                    self.error = True
            if( (name is not None) and
                (ip_address is not None) and
                (network is not None) and
                (netmask is not None) and
                (listen_port is not None) and
                (config_dir is not None)
                ):
                if debug:
                    print("Reading server configuration arguments")
                self.set_name(name)
                self.set_ip_address(ip_address)
                self.set_network(network)
                self.set_netmask(netmask)
                self.set_listen_port(listen_port)
                self.set_config_dir(config_dir)
                self.set_wan_if(wan_if)
                self.set_gateway(gateway)
                self.set_server_ip(server_ip)
                self.set_allowed_ips()
                self.generate_config(generate_keys = True)
        else:
            self.read_from_file = True
            self.loaded = False
            if debug:
                print(f"Reading server configuration from '{dump_file}'")
            self.load_config(data_dump)
            self.generate_config(generate_keys = False)
            if debug:
                self.print_config()
            self.loaded = True
        if not self.write_config():
            print("Failed to write server configuration")
            self.error = True
        elif debug:
            print(f"\n\n========Initialized========\n\n")

    ##set functions
    def set_name(self, name):
        self.name = name
        if self.debug:
            self.print_config_string('name')

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address
        if self.debug:
            self.print_config_string('ip_address')

    def set_network(self, network):
        self.network = network
        if self.debug:
            self.print_config_string('network')

    def set_netmask(self, netmask):
        self.netmask = netmask
        if self.debug:
            self.print_config_string('netmask')

    def set_listen_port(self, listen_port):
        self.listen_port = listen_port
        if self.debug:
            self.print_config_string('listen_port')

    def set_gateway(self, gateway = None):
        if (not hasattr(self, 'network')) or (self.network is None):
            print("Network must be set to configure gateway interface")
            return False
        if (hasattr(self, 'gateway')) and (self.gateway is not None):
            if (self.gateway == 'y') and (not self.remove_gateway()):
                print("Failed to remove existing gateway configuration")
                return False
        if gateway is not None:
            if gateway == 'y':
                if self.debug:
                    print("Configuring server as a gateway")
                self.gateway = gateway
                return self.set_wan_if(self.wan_if)
        if self.debug:  
            print("Not configuring server as a gateway")
        self.gateway = 'n'
        return self.set_wan_if(self.wan_if)
                
    def set_wan_if(self, wan_if):
        #update NAT rules
        if self.debug:
            print("Adding NAT rules to iptables")
        self.wan_if = wan_if
        if self.debug:
            self.print_config_string('wan_if')
        if self.set_server_ip() and self.set_post_up() and self.set_post_down() and self.set_allowed_ips(): 
            return self.generate_config()

    def set_server_ip(self, server_ip = None):
        if server_ip is not None:
            self.server_ip = server_ip
        elif (hasattr(self, 'wan_if')) and (self.wan_if is not None):
            #get external IP address
            try:
                server_ip = os.popen('ip a show ' + self.wan_if).read().split("inet ")[1].split("/")[0]
                self.server_ip = server_ip
            except:
                print("Failed to determine public IP address")
                return False
        else:
            print("WAN interface is not set")
            return False
        if (hasattr(self, 'ports')) and (self.ports is not None):
            for port in self.ports.values():
                port['wan_ip'] = server_ip
        if (hasattr(self,  'peers')) and (self.peers is not None):
            for peer in self.peers.values():
                peer.endpoint_ip = server_ip
        if self.debug:
            self.print_config_string('server_ip')
        return True

    def set_dns_server(self, dns_server):
        self.dns_server = dns_server
        if (hasattr(self, 'peers')) and (self.peers is not None):
            for peer in self.peers.values():
                if not peer.set_dns_server(dns_server):
                    print(f"Failed to set DNS server for peer '{peer.name}'")
                    return False
        if self.debug:
            self.print_config_string('dns_server')
        return True

    def set_persistent_keepalive(self, persistent_keepalive):
        self.persistent_keepalive = persistent_keepalive
        if (hasattr(self, 'peers')) and (self.peers is not None):
            for peer in self.peers.values():
                if not peer.set_persistent_keepalive(persistent_keepalive):
                    print(f"Failed to set persistent keepalive interval for peer '{peer.name}'")
                    return False
        if self.debug:
            self.print_config_string('persistent_keepalive')
        return True

    def set_config_dir(self, config_dir):
        self.config_dir = config_dir
        if self.debug:
            self.print_config_string('config_dir')

    def set_private_key(self, private_key):
        self.private_key = private_key
        if self.debug:
            self.print_config_string('private_key')

    def set_public_key(self, public_key):
        self.public_key = public_key
        if self.debug:
            self.print_config_string('public_key')

    def set_pre_up(self, pre_up = None):
        #Generate base pre_up
        base_pre_up = [
            ('ip link add ' + self.name + ' type wireguard'),
            ('wg setconf ' + self.name + ' ' + self.config_dir + '/' + self.name + '.conf'),
        ]
        if (hasattr(self, 'peers')) and (self.peers is not None):
            for peer in self.peers.values():
                base_pre_up.append('wg addconf ' + self.name + ' ' + self.config_dir + '/' + self.name + '-' + peer.name + '.conf')
        if pre_up is not None:
            self.pre_up = pre_up
        else:
            self.pre_up = base_pre_up
        if self.debug:
            self.print_config_list('pre_up')
        return True

    def set_post_up(self, post_up = None):
        #generate base post_up
        if (not hasattr(self, 'wan_if')) or  (self.wan_if is None):
            print("WAN interface must be set to generate post up rules")
            return False
        base_post_up = [
            ('iptables -A FORWARD -i ' + self.wan_if + ' -o ' + self.name + ' -d ' + self.network + ' -j ACCEPT'),
            ('iptables -A FORWARD -i ' + self.name + ' -o ' + self.name + ' -s ' + self.network + ' -d ' + self.network + ' -j ACCEPT'),
            ('iptables -A INPUT --proto udp --dport ' + self.listen_port + ' -i ' + self.wan_if + ' -j ACCEPT'),
        ]
        if (hasattr(self, 'gateway')) and (self.gateway is not None) and self.gateway == 'y':
            base_post_up.append('iptables -A FORWARD -i ' + self.name + ' -s ' + self.network + ' -o ' + self.wan_if + ' -j ACCEPT'),
            base_post_up.append('iptables -t nat -A POSTROUTING -s ' + self.network + ' -o ' + self.wan_if + ' -j MASQUERADE')
            if (hasattr(self, 'ports')) and (self.ports is not None):
                for port in self.ports.values():
                    protocol = port.get('protocol')
                    destination_port = port.get('wan_port')
                    destination_ip = port.get('wan_ip')
                    target_ip = port.get('lan_ip')
                    target_port = port.get('lan_port')
                    if protocol != 'both':
                        #forwarded port input accept rule
                        #base_post_up.append('iptables -A INPUT -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.wan_if + ' -j ACCEPT')
                        #forwarded port nat rule
                        #base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.name +' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.wan_if +' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                    else:
                        #base_post_up.append('iptables -A INPUT -d ' + destination_ip + ' -p udp --dport ' + destination_port + ' -i ' + self.wan_if + ' -j ACCEPT')
                        #base_post_up.append('iptables -A INPUT -d ' + destination_ip + ' -p tcp --dport ' + destination_port + ' -i ' + self.wan_if + ' -j ACCEPT')
                        #base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p udp --dport ' + destination_port + ' -i ' + self.name + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        #base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p tcp --dport ' + destination_port + ' -i ' + self.name + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p udp --dport ' + destination_port + ' -i ' + self.wan_if + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_up.append('iptables -t nat -A PREROUTING -d ' + destination_ip + ' -p tcp --dport ' + destination_port + ' -i ' + self.wan_if + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
        if post_up is not None:
            self.post_up = post_up
        else:
            self.post_up = base_post_up
        if self.debug:
            self.print_config_list('post_up')
        return True

    def set_post_down(self, post_down = None):
        #generate base post_down
        if (not hasattr(self, 'wan_if')) or  (self.wan_if is None):
            print("WAN interface must be set to generate post up rules")
            return False
        base_post_down = [
            ('ip link del ' + self.name),
            ('iptables -D FORWARD -i ' + self.wan_if + ' -o ' + self.name + ' -d ' + self.network + ' -j ACCEPT'),
            ('iptables -D FORWARD -i ' + self.name + ' -o ' + self.name + ' -s ' + self.network + ' -d ' + self.network + ' -j ACCEPT'),
            ('iptables -D INPUT --proto udp --dport ' + self.listen_port + ' -i ' + self.wan_if + ' -j ACCEPT'),
        ]
        if (hasattr(self, 'gateway')) and (self.gateway is not None) and self.gateway == 'y':
            base_post_down.append('iptables -D FORWARD -i ' + self.name + ' -s ' + self.network + ' -o ' + self.wan_if + ' -j ACCEPT'),
            base_post_down.append('iptables -t nat -D POSTROUTING -s ' + self.network + ' -o ' + self.wan_if + ' -j MASQUERADE')
            if (hasattr(self, 'ports')) and (self.ports is not None):
                for port in self.ports.values():
                    protocol = port.get('protocol')
                    destination_port = port.get('wan_port')
                    destination_ip = port.get('wan_ip')
                    target_ip = port.get('lan_ip')
                    target_port = port.get('lan_port')
                    if protocol != 'both':
                        #forwarded port input accept rule
                        #base_post_down.append('iptables -D INPUT -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.wan_if + ' -j ACCEPT')
                        #forwarded port nat rule
                        #base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.name + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p ' + protocol + ' --dport ' + destination_port + ' -i ' + self.wan_if + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                    else:
                        #base_post_down.append('iptables -D INPUT -d ' + destination_ip + ' -p udp --dport ' + destination_port +  ' -i ' + self.wan_if + ' -j ACCEPT')
                        #base_post_down.append('iptables -D INPUT -d ' + destination_ip + ' -p tcp --dport ' + destination_port +  ' -i ' + self.wan_if + ' -j ACCEPT')
                        #base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p udp --dport ' + destination_port +  ' -i ' + self.name + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        #base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p tcp --dport ' + destination_port +  ' -i ' + self.name + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p udp --dport ' + destination_port +  ' -i ' + self.wan_if + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
                        base_post_down.append('iptables -t nat -D PREROUTING -d ' + destination_ip + ' -p tcp --dport ' + destination_port +  ' -i ' + self.wan_if + ' -j DNAT --to-destination ' + target_ip + ":" + target_port)
        if post_down is not None:
            self.post_down = post_down
        else:
            self.post_down = base_post_down
        if self.debug:
            self.print_config_list('post_down')
        return True

    def set_server_config(self, server_config):
        self.server_config = server_config
        if self.debug:
            self.print_config_list('server_config')

    def set_interface_config(self, interface_config):
        self.interface_config = interface_config
        if self.debug:
            self.print_config_list('interface_config')

    def set_allowed_ips(self, allowed_ips = None):
        #generate base allowed_ips
        if (hasattr(self, 'network')) and (self.network is not None):
            base_allowed_ips = [self.network]
        else: 
            print("Network is required to generate allowed ips")
            return False
        if (hasattr(self, 'gateway')) and (self.gateway is not None) and self.gateway == 'y':
            base_allowed_ips.append('0.0.0.0/0')
        if allowed_ips is not None:
            self.allowed_ips = allowed_ips
        else:
            self.allowed_ips = base_allowed_ips
        #update allowed ips in all clients
        if (hasattr(self, 'peers')) and (self.peers is not None):
            for peer in self.peers.values():
                peer.set_allowed_ips(self.allowed_ips)
        if self.debug:
            self.print_config_list('allowed_ips')
        return True
    
    def set_ports(self, ports):
        self.ports = ports
        if self.debug:
            self.print_ports()
    
    def set_peers(self, peers):
        self.peers = peers
        if self.debug:
            self.print_peers()

    def remove_gateway(self):
        """Removes the gateway configuration rules"""
        if (hasattr(self, 'gateway')) and (self.gateway is not None):
            if self.debug:
                print("Already configured as a gateway, clearing rules")
            self.gateway = 'n'
        else:
            if self.debug:
                print("Server is not configured as a gateway")
                return False
        if self.generate_config() and self.write_config():
            return self.set_wan_if(self.wan_if)
        else:
            return False
        
    def print_config_string(self, attribute):
        """prints a configuration string"""
        if hasattr(self, attribute):
            if getattr(self, attribute) is not None:
                description = self.attribute_index[attribute]
                value = getattr(self, attribute)
                print("%-48s %s" % (description, value))
            else:
                if self.debug:
                    print(f"Attribute '{attribute}' is not set")
                return False
        else:
            if self.debug:
                print(f"Attribute '{attribute}' not found")
                return False
        return True

    def print_config_list(self, attribute):
        """prints a configuration list"""
        if hasattr(self, attribute):
            if getattr(self, attribute) is not None:
                description = self.attribute_index[attribute]
                values = getattr(self, attribute)
                print(f"{description}\n========")
                for line in values:
                    print(line)
                print("========")
            else:
                if self.debug:
                    print(f"Attribute '{attribute}' is not set")
                return False
        else:
            if self.debug:
                print(f"Attribute '{attribute}' not found")
            return False
        return True

    def print_peers(self):
        """prints a configuration dict"""
        if (hasattr(self, 'peers')) and (self.peers is not None):
            print("++++++++++++++++")
            for peer in self.peers.values():
                print("%-32s %-48s %s" % (peer.name, peer.public_key, peer.ip_address))
            print("++++++++++++++++")
        else:
            print("No peers found")
        return False

    def print_config(self):
        """prints all server configuration"""
        print_attributes = [
            'name',
            'wan_if',
            'gateway',
            'allowed_ips',
            'dns_server',
            'persistent_keepalive',
            'server_ip',
            'listen_port',
            'ip_address',
            'network',
            'config_dir',
            'public_key',
        ]

        for attribute in print_attributes:
            if hasattr(self, attribute):
                if isinstance(getattr(self, attribute), list):
                    self.print_config_list(attribute)
                elif isinstance(getattr(self, attribute), str):
                    self.print_config_string(attribute)
                else:
                    if self.debug:
                        print(f"ATTRIBUTE '{attribute}' HAS UNKNOWN TYPE OF '{getattr(self, attribute)}'")
            else:
                if self.debug:
                    print(f"ATTRIBUTE '{attribute}' NOT FOUND")
        return True
        
    def print_ports(self):
        """prints all forwarded ports"""
        if (hasattr(self, 'ports')) and (self.ports is not None):
            print("****************")
            for port in self.ports.values():
                print(f"Rule name: {port.get('name')}\n\t{port.get('wan_ip')}:{port.get('wan_port')} -{port.get('protocol')}-> {port.get('lan_ip')}:{port.get('lan_port')}")
                print("****************")
        else:
            print("No port forwarding rules found")
            return False
        return True
        
    def add_port(self, name, protocol, lan_port, lan_ip, wan_port):
        """Adds a port forward rule to the server"""
        wan_ip = self.server_ip
        try:
            protocol = protocol.lower()
        except:
            print("Invalid string")
            return False
        if (protocol != 'tcp') and (protocol != 'udp') and (protocol != 'both'):
            print("Invalid protocol")
            return False
        if (not hasattr(self, 'peers')) or (self.peers is None):
            print("No peers found, you need to add a peer before you can forward a port")
            return False
        try:
            int(wan_port)
            int(lan_port)
        except:
            print("Listen port must be a number")
            return False
        if (int(wan_port) < 1) or (int(wan_port) > 65535) or (int(lan_port) < 1) or (int(lan_port) > 65535):
            print("Invalid listen port specified")
            return False
        ip_valid = False
        for peer in self.peers.values():
            if peer.ip_address == lan_ip:
                ip_valid = True
        if not ip_valid:
            print("IP address is not in use by any peer")
            return False
        ports = None
        if (hasattr(self, 'ports')) and (self.ports is not None):
            if name in self.ports:
                print(f"A rule by '{name}' already exists")
                return False
            if ((protocol == 'udp') or (protocol == 'both')) and (self.listen_port == wan_port):
                print(f"Listen port already in use by the wireguard server interface")
                return False
            for port in self.ports.values():
                if (port.get('wan_port') == wan_port) and ((port.get('protocol') == protocol) or (port.get('protocol') == 'both')):
                    print(f"WAN port '{wan_port}' (protocol = {protocol}) already in use by rule '{port.get('name')}'")
                    return False
            ports = self.ports
        if ports is not None:
            ports.update({name : { 'name' : name, 'protocol' : protocol, 'wan_ip' : wan_ip, 'wan_port' : wan_port, 'lan_ip' : lan_ip, 'lan_port' : lan_port}})
        else:
            ports = {name : { 'name' : name, 'protocol' : protocol, 'wan_ip' : wan_ip, 'wan_port' : wan_port, 'lan_ip' : lan_ip, 'lan_port' : lan_port}}
        self.set_ports(ports)
        return self.generate_config()
        
    def del_port(self, name):
        """Deletes a port rule from the server"""
        if (hasattr(self, 'ports')) and (self.ports is not None):
            if name in self.ports:
                del self.ports[name]
            else:
                print(f"Port rule by name '{name}' not found")
                return False
        else:
            print("No ports found")
            return False
        #set ports to none if last port deleted
        if not self.ports:
            self.ports = None
        return self.generate_config()
        
    def dump_config(self):
        """dumps all config to a file"""
        server_dump_file = self.config_dir + '/' + self.name + '-data-dump.json'
        config = None
        #build config dict
        for attribute in self.attribute_index:
            if hasattr(self, attribute):
                if getattr(self, attribute) is not None:
                    if attribute == 'peers':
                        if self.debug:
                            print(f"Reading peers")
                        peer_config = None
                        peer_data = getattr(self, attribute)
                        for peer_name in peer_data:
                            peer_dump = peer_data.get(peer_name).dump_config()
                            if self.debug:
                                print(f"Peer data for {peer_name}: {peer_dump}")
                            if peer_config is None:
                                peer_config = {peer_name : peer_dump}
                            else:
                                peer_config.update({peer_name : peer_dump})
                        config_entry = {attribute: peer_config}
                    else:
                        if self.debug:
                            print(f"Configuration attribute '{attribute}' read")
                        config_entry = {attribute : getattr(self, attribute)}
                    try:
                        config.update(config_entry)
                    except:
                        config = config_entry
                elif self.debug:
                    print(f"Configuration attribute '{attribute}' is empty")
            elif self.debug:
                print(f"Configuration attribute '{attribute}' not set")
        if self.debug:
            #delete existing config
            if os.path.isfile(server_dump_file):
                try:
                    os.remove(server_dump_file)
                except OSError:
                    print("Failed to delete old configuration file")
                    return False
            #write server configuration dump
            print(f"Writing server configuration to '{server_dump_file}'")
            if not self.debug:
                try:
                    with open(server_dump_file, 'a') as file:
                        json.dump(config, file)
                except PermissionError:
                    print("Unable to write file. Permission denied")
                return False
            #protect server configuration dump
            print(f"Changing the file permissions of '{server_dump_file}' to '600'")
            try:
                os.chmod(server_dump_file, 0o600)
            except PermissionError:
                print("Unable to change file permissions. Permission denied")
                return False
        return config

    def load_config(self, data_dump):
        """loads all config from server config dump"""
        if self.debug:
            print(f"Loading config")
        try:
            for name in data_dump:
                if (name == 'peers') and (data_dump.get('peers') is not None):
                    if self.debug:
                        print("Reading peers")
                    peers = data_dump.get(name)
                    for peer in peers.values():
                        self.load_peer(peer)
                else:
                    if self.debug:
                        print(f"Setting attribute name '{name}' to value '{data_dump.get(name)}'")
                    getattr(self, 'set_' + name)(data_dump.get(name))
        except:
            print("Failed to load config")
            return False
        self.loaded = True
        return True

    def generate_config(self, generate_keys = False):
        """Rebuilds all config"""
        if generate_keys or (not hasattr(self, 'public_key')) or (not hasattr(self, 'private_key')):
            if not self.generate_keys():
                print("Failed to generate new keys")
                return False
        if not self.generate_server_config():
            print("Failed to generate server configuration")
            return False
        if not self.generate_interface_config():
            print("Failed to generate interface configuration.....how?")
            return False
        if hasattr(self, 'peers') and self.peers is not None:
            for peer in self.peers.values():
                if not peer.generate_config():
                    print(f"Failed to genreate peer configuration for peer '{peer.name}'")
                    return False
        return True

    def write_config(self):
        """Writes all required server configuration"""
        if (hasattr(self, 'interface_config')) and (getattr(self, 'interface_config') is not None):
            if not self.write_interface_config():
                print("Failed to write interface config")
                return False
        if (hasattr(self, 'server_config')) and (getattr(self, 'server_config') is not None):
            if not self.write_server_config():
                print("Failed to write server config")
                return False
        if (hasattr(self, 'peers')) and (getattr(self, 'peers') is not None) and self.peers:
            if not self.write_all_peer_configs():
                print("Failed to write peer configuration files")
                return False
        return True

    def generate_keys(self):
        """Generates a new key pair"""
        #create private key
        if self.debug:
            print("Generating the private key")
        cmd = subprocess.run(['wg', 'genkey'], stdout = subprocess.PIPE)
        if cmd.returncode != 0:
            print("Failed to generate private key")
            return False
        cmd_input = cmd.stdout
        private_key = cmd_input.decode('utf-8').rstrip()
        self.set_private_key(private_key)
        #derive public key
        if self.debug:
            print("Deriving the public key")
        cmd = subprocess.run(['wg', 'pubkey' ], stdout = subprocess.PIPE, input = cmd_input)
        if cmd.returncode != 0:
            print("Failed to derive public key")
            return False
        public_key = cmd.stdout.decode('utf-8').rstrip()
        self.set_public_key(public_key)
        return True

    def write_keys(self):
        """Writes the key pair to files """
        if not hasattr(self, 'private_key'):
            print("Private key not loaded")
            return False
        if not hasattr(self, 'public_key'):
            print("Private key not loaded")
            return False
        private_file = self.config_dir + '/' + self.name + '-private.key'
        public_file = self.config_dir + '/' + self.name + '-public.key'
        #Mdelete existing private key
        if os.path.isfile(private_file):
            try:
                os.remove(private_file)
            except OSError:
                print("Failed to delete existing private key file file")
                return False
        #delete existing public key
        if os.path.isfile(public_file):
            try:
                os.remove(public_file, old_public_file)
            except OSError:
                print("Failed to delete existing public key file")
                return False
        #write files
        if self.debug:
            print(f"Writing private key file to '{private_file}'")
        try:
            with open(private_file, 'w') as file:
                file.write(self.private_key)
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False
        #protect private key
        if self.debug:
            print(f"Changing the file permissions of '{private_file}' to '600'")
        try:
            os.chmod(private_file, 0o600)
        except PermissionError:
            print("Unable to change file permissions. Permission denied")
            return False

        if self.debug:
            print(f"Writing public key to '{public_file}'")
        try:
            with open(public_file, 'w') as file:
                file.write(self.public_key)
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False

    def read_keys(self):
        """Reads the key pair from files"""
        private_file = self.config_dir + '/' + self.name + '-private.key'
        public_file = self.config_dir + '/' + self.name + '-public.key'
        #check if keys exist
        if (not os.path.isfile(private_file)) or (not os.path.isfile(public_file)):
            print("Keyfiles not found, you need to create them first")
            return False
        #read private key
        if self.debug:
            print(f"Reading private key file '{private_file}'")
        try:
            with open(private_file, 'r') as file:
                private_key = file.read()
        except PermissionError:
            print("Unable to read file. Permission denied")
            return False
        #read public key
        if self.debug:
            print(f"Reading public key file '{public_file}'")
        try:
            with open(public_file, 'r') as file:
                public_key = file.read()
        except PermissionError:
            print("Unable to read file. Permission denied")
            return False
        self.set_private_key(private_key)
        self.set_public_key(public_key)
        return True

    def delete_keys(self):
        """Deletes the key pair files"""
        private_file = self.config_dir + '/' + self.name + '-private.key'
        public_file = self.config_dir + '/' + self.name + '-public.key'
        #Check if private key file exists and delete it
        if os.path.isfile(private_file):
            if self.debug:
                print(f"Deleting private key file at '{private_file}'")
            try:
                os.remove(private_file)
            except OSError:
                print("Failed to delete file")
                return False
        elif self.debug:
            print("Private key file not found")
        #Check if public key file exists and delete
        if os.path.isfile(public_file):
            if self.debug:
                print(f"Deleting public key file at '{private_file}'")
            try:
                os.remove(public_file)
            except OSError:
                print("Failed to delete file")
                return False
        elif self.debug:
            print("Public key file not found")
        return True

    def generate_interface_config(self):
        """Generates wireguard network interface configuration"""
        #regenerate itnerface rules
        if not (self.set_post_up() and self.set_post_down() and self.set_pre_up()):
            print("Failed to generate interface rules")
            return False
        #Build congfig using server information
        config = ['auto ' + self.name]
        config.append('iface ' + self.name + ' inet static')
        config.append('\taddress ' + self.ip_address)
        config.append('\tnetmask ' + self.netmask)
        for rule in self.pre_up:
            config.append('\tpre-up ' + rule)
        for rule in self.post_up:
            config.append('\tpost-up ' + rule)
        for rule in self.post_down:
            config.append('\tpost-down ' + rule)
        self.set_interface_config(config)
        return True

    def write_interface_config(self):
        """Writes wireguard network interface configuration to a file"""
        if not hasattr(self, 'interface_config'):
            print("Interface config not loaded")
            return False
        network_config_file = '/etc/network/interfaces.d/99-wireguard-' + self.name + '.cfg'
        #delete existing config
        if os.path.isfile(network_config_file):
            try:
                os.remove(network_config_file)
            except OSError:
                print("Failed to delete existing network configuration file")
                return False
        #write config
        if self.debug:
            print(f"Writing network configuration to '{network_config_file}'")
        try:
            with open(network_config_file, 'a') as file:
                for config in self.interface_config:
                    file.write(config + '\n')
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False
        return True

    def read_interface_config(self):
        """Reads the wireguard network interface configuration from a file"""
        network_config_file = '/etc/network/interfaces.d/99-wireguard-' + self.name + '.cfg'
        #check if configuration exists
        if not os.path.isfile(network_config_file):
            print("Network configuration not found, you need to create it first")
            return False
        #read
        if self.debug:
            print(f"Reading network configuration from '{network_config_file}'")
        try:
            with open(network_config_file, 'r') as file:
                config = file.readlines()
            config = [l.rstrip('\n') for l in config]
        except PermissionError:
            print("Unable to read file. Permission denied")
            return False
        self.set_interface_config(config)
        return True

    def delete_interface_config(self):
        """Deletes the wireguard network interface configuration file"""
        network_config_file = '/etc/network/interfaces.d/99-wireguard-' + self.name + '.cfg'
        #check if network interface configuration file exists and delete it
        if os.path.isfile(network_config_file):
            if self.debug:
                print(f"Deleting network configuration file at '{network_config_file}'")
            try:
                os.remove(network_config_file)
            except OSError:
                print("Failed to delete file")
                return False
        else:
            print("Network configuration file not found")
        return True

    def generate_server_config(self):
        """Generate the wireguard server config"""
        if not hasattr(self, 'private_key'):
            print("Private key not loaded into memory")
            return False
        if not hasattr(self, 'listen_port'):
            print("Listen port not loaded into memory")
            return False
        #generate config
        config = ['#' + self.name]
        config.append('[Interface]')
        config.append('PrivateKey = ' + self.private_key)
        config.append('ListenPort = ' + self.listen_port)
        self.set_server_config(config)
        return True

    def write_server_config(self):
        """Write the wireguard server configuration to a file"""
        if not hasattr(self, 'server_config'):
            print("No server configuration loaded")
            return False
        #check for server config dir and create it if it doesn't exist
        if not os.path.isdir(self.config_dir):
            if self.debug:
                print(f"Server directory '{self.config_dir}' not found, creating it")
            try:
                os.mkdir(self.config_dir)
            except OSError:
                print("Unable to create server directory")
        server_config_file = self.config_dir + '/' + self.name + '.conf'
        #check if config already exists
        if os.path.isfile(server_config_file):
            try:
                os.remove(server_config_file)
            except OSError:
                print("Failed to delete existing server configurationfile")
                return False
        #write config
        if self.debug:
            print(f"Writing server configuration to '{server_config_file}'")
        try:
            with open(server_config_file, 'a') as file:
                for config in self.server_config:
                    file.write(config + '\n')
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False
        return True

    def read_server_config(self):
        """Reads the wireguard server configuration from a file"""
        server_config_file = self.config_dir + '/' + self.name + '.conf'
        #Check if configuration file exists
        if not os.path.isfile(server_config_file):
            print("Server configuration not found, you need to create it first")
            return False
        #read
        if self.debug:
            print(f"Reading server confiuration from '{server_config_file}'")
        try:
            with open(server_config_file, 'r') as file:
                config = file.readlines()
            config = [l.rstrip('\n') for l in config]
        except PermissionError:
            print("Unable to read file. Permission denied")
            return False
        self.set_server_config(config)
        return True

    def delete_server_config(self):
        """Deletes the wireguard server configuration file"""
        server_config_file = self.config_dir + '/' + self.name + '.conf'
        #Check if server configuration file exists and delete it
        if os.path.isfile(server_config_file):
            if self.debug:
                print(f"Deleting server configuration file at '{server_config_file}'")
            try:
                os.remove(server_config_file)
            except OSError:
                print("Failed to delete file")
                return False
        elif self.debug:
            print("Server configuration file not found")
        return True

    def check_peer_name(self, peer_name):
        """Checks if a peer user name is valid"""
        if (hasattr(self, 'peers')) and (self.peers is not None):
            #get peer names
            if self.debug:
                print("Checking if peer exists")
            if peer_name in self.peers:
                print(f"Peer '{peer_name}' already exists")
                return False
        return True
        
    def check_peer_key(self, public_key):
        """Checks if a peer public key is valid"""
        if (hasattr(self, 'peers')) and (self.peers is not None):
            #get peer public keys
            if self.debug:
                print("Checking if peer public key exists")
            for peer in self.peers.values():
                if public_key == peer.public_key:
                    print(f"Peer with public key '{public_key}' already exists")
                    return False
            if public_key in self.peers:
                print(f"Peer '{peer_name}' already exists")
                return False
        return True

    def check_peer_ip(self, peer_ip):
        """Checks if peer ip address is valid"""
        #Don't check saved config
        if (
            (hasattr(self, 'read_from_file')) and 
            (hasattr(self, 'loaded')) and
            (self.read_from_file is not None) and 
            (self.loaded is not None) and
            (self.read_from_file) and 
            (not self.loaded)
            ):
            return True
        #check that ip is valid
        try:
            ip_address = ipaddress.IPv4Interface(peer_ip)
        except:
            print("Invalid IP address specified")
            return False
        #check if this is the first peer
        if (hasattr(self, 'peers')) and (self.peers is not None):
            #get peer ips and names
            if self.debug:
                print("Getting peer IPs")
            peer_data = None
            for peer in self.peers.values():
                if peer_data is None:
                    peer_data = {peer.name : peer.ip_address}
                else:
                    peer_data.update({peer.name : peer.ip_address})
            if self.debug:
                print("%-32s %s" % (peer.name, peer.ip_address))
            #check if ip is set
            if peer_ip in peer_data.values():
                print(f"IP '{peer_ip}' already in use")
                return False
        #Check ip format
        wireguard_network = ipaddress.IPv4Network(self.network)
        peer_address = ip_address.ip
        #check that ip is in the wireguard network
        if peer_address not in wireguard_network.hosts():
            print(f"IP '{peer_ip}' is not in wireguard network '{self.network}'")
            return False
        #check that the ip is not the server ip
        if str(peer_address) == self.ip_address:
            print("Peer IP and server IP cannot be the same")
            return False
        return True

    def add_peer(self, peer_name, peer_ip, public_key = None):
        """Adds a peer to the list of peers in the server"""
        if (not self.check_peer_name(peer_name)) or (not self.check_peer_ip(peer_ip)):
            print(f"Invalid configuration for peer '{peer_name}'")
            return False
        #create new peer
        peer = WgClient(
            name = peer_name,
            ip_address = peer_ip,
            public_key = public_key,
            allowed_ips = self.allowed_ips,
            endpoint_ip = self.server_ip,
            endpoint_port = self.listen_port,
            endpoint_public_key = self.public_key,
            debug = self.debug,
        )
        #add optional arguments if they are passed
        if (hasattr(self, 'dns_server')) and (self.dns_server is not None):
            peer.set_dns_server(self.dns_server)
        if (hasattr(self, 'persistent_keepalive')) and (self.persistent_keepalive is not None):
            peer.set_persistent_keepalive(self.persistent_keepalive)
        #add peer to server
        if (hasattr(self, 'peers')) and (getattr(self, 'peers') is not None) and self.peers:
            self.peers.update({peer_name : peer})
            if self.debug:
                self.print_peers()
        else:
            self.set_peers({peer_name : peer})
        if self.generate_config() and self.write_config():
            return True
        else:
            return False

    def del_peer(self, peer_name):
        """Deletes a peer and their configuration"""
        deleted = False
        #check if peer exists
        if (hasattr(self, 'peers')) and (getattr(self, 'peers') is not None):
            if peer_name in self.peers:
                del self.peers[peer_name]
                deleted = True
                if self.debug:
                    print(f"Deleted peer '{peer_name}' from the server")
                #set peers to none if it is empty
                if not self.peers:
                    if self.debug:
                        print("The server now has no peers")
                    self.peers = None
            else:
                print(f"Peer '{peer_name}' not found")
        #check if config exists
        peer_config_file = self.config_dir + '/' + self.name + '-' + peer_name + '.conf'
        if os.path.isfile(peer_config_file):
            if self.debug:
                print(f"Deleting peer configuration file for peer '{peer_name}'")
            try:
                os.remove(peer_config_file)
                deleted = True
            except OSError:
                print(f"Failed to remove peer configuration file for peer '{peer_name}'")
                return False
        elif self.debug:
            print("Peer configuration file not found")
        if not deleted:
            print(f"Peer '{peer_name}' does not exist")
        #Set peers to none if last peer deleted
        if not self.peers:
            self.peers = None
        if deleted and self.generate_config() and self.write_config():
            return True
        else:
            return False

    def load_peer(self, data_dump):
        """Loads a peer from a data dump"""
        if self.debug:
            print(data_dump)
        peer_name = data_dump.get('name')
        peer_ip = data_dump.get('ip_address')
        if not self.check_peer_name(peer_name):
            print(f"Failed to load peer '{peer_name}', already exists")
            return False
        if not self.check_peer_ip(peer_ip):
            print(f"Failed to load peer '{peer_name}', ip conflict")
            return False
        try:
            peer = WgClient(data_dump = data_dump)
        except:
            print("Failed to create peer object")
            return False
        #add peer to server
        if (hasattr(self, 'peers')) and (self.peers is not None):
            self.peers.update({peer_name : peer})
            if self.debug:
                self.print_peers()
        else:
            self.set_peers({peer_name : peer})

    def write_peer_config(self, peer_name):
        """Writes peer configuration to a file"""
        #check that peers exist
        if (not hasattr(self, 'peers')) or self.peers is None:
            print("No peers found")
            return False
        #check that peer name is valid
        if peer_name not in self.peers:
            print(f"Peer '{peer_name}' not found")
            return False
        #check for server config dir and create it if it doesn't exist
        if not os.path.isdir(self.config_dir):
            if self.debug:
                print(f"Server directory '{self.config_dir}' not found, creating it")
            try:
                os.mkdir(self.config_dir)
            except OSError:
                print("Unable to create server directory")
        #check if config already exists
        peer_config_file = self.config_dir + '/' + self.name + '-' + peer_name + '.conf'
        if os.path.isfile(peer_config_file):
            try:
                os.remove(peer_config_file)
            except OSError:
                print("Failed to delete existing configuration file")
                return False
        #get peer config
        peer = self.peers.get(peer_name)
        if (not hasattr(peer, 'peer_config')) or peer.peer_config is None:
            if self.debug:
                print(f"Peer configuration for '{peer_name}' not found, generating it")
            peer.generate_peer_config()
        config = peer.peer_config
        #write config
        if self.debug:
            print(f"Writing peer configuration to '{peer_config_file}'")
        try:
            with open(peer_config_file, 'a') as file:
                for line in config:
                    file.write(line + '\n')
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False
        return True

    def write_all_peer_configs(self):
        """Writes all peer configurations to a file"""
        #check that peers exist
        if (not hasattr(self, 'peers')) or self.peers is None:
            print("No peers found")
            return False
        for peer_name in self.peers:
            if self.debug:
                print(f"Writing config for peer '{peer_name}'")
            self.write_peer_config(peer_name)
        return True

    def print_client_config(self, peer_name):
        """Prints the client configuration for a peer"""
        #check that peers exist
        if (not hasattr(self, 'peers')) or self.peers is None:
            print("No peers found")
            return False
        #check that peer name is valid
        if peer_name not in self.peers:
            print(f"Peer '{peer_name}' not found")
            return False
        #print client config
        if not self.peers.get(peer_name).print_client_config():
            print(f"Failed to print client config for peer '{peer_name}'")
            return False
        return True
