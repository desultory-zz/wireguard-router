#!/usr/bin/env python3
import subprocess
import ipaddress

class WgClient(object):
    """WgClient class, holds wireguard client information"""
    attribute_index = {
        'name' : 'Client name',
        'ip_address' : 'Client IP address',
        'ip_network' : 'Client IP network',
        'allowed_ips' : 'Alowed IPs',
        'endpoint_ip' : 'Wireguard Server IP',
        'endpoint_port' : 'Wireguard server port',
        'endpoint_public_key' : 'Wireguard server public key',
        'private_key' : 'Client private key',
        'public_key' : 'Client public key',
        'dns_server' : 'Client DNS server',
        'persistent_keepalive' : 'Client keepalive interval',
        'peer_config' : 'Peer configuration for wireguard server',
        'client_config' : 'Client configuration file for peer',
    }
    def __init__(
        self, name = None,
        ip_address = None,
        public_key = None,
        allowed_ips = None,
        endpoint_ip = None,
        endpoint_port = None,
        endpoint_public_key = None,
        dns_server = None,
        persistent_keepalive = None,
        debug = False,
        data_dump = None,
    ):
        """initializes the object"""
        self.debug = debug
        if debug:
            print(f"Client debugging enabled")

        if data_dump is not None:
            if debug:
                print("Reading client configuration from data dump")
            self.read_config(data_dump)
            if debug:
                self.print_config()
        elif(
            (name is not None) and
            (ip_address is not None) and
            (allowed_ips is not None) and
            (endpoint_ip is not None) and
            (endpoint_port is not None) and
            (endpoint_public_key is not None)
        ):
            ip_interface = ipaddress.IPv4Interface(ip_address)
            client_ip_address = str(ip_interface.ip)
            self.set_name(name)
            self.set_ip_address(client_ip_address)
            self.set_ip_network(client_ip_address)
            self.set_allowed_ips(allowed_ips)
            self.set_endpoint_ip(endpoint_ip)
            self.set_endpoint_port(endpoint_port)
            self.set_endpoint_public_key(endpoint_public_key)
            if dns_server is not None:
                self.set_dns_server(dns_server)
            if persistent_keepalive is not None:
                self.set_persistent_keepalive(persistent_keepalive)
            if public_key is not None:
                self.set_public_key(public_key)
                self.set_private_key('<UNKNOWN>')
                self.generate_config()
            else:
                self.generate_config(generate_keys = True)

    def set_name(self, name):
        self.name = name
        if self.debug:
            self.print_config_string('name')
        return True

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address
        if self.debug:
            self.print_config_string('ip_address')

    def set_ip_network(self, ip_network):
        self.ip_network = ip_network
        if self.debug:
            self.print_config_string('ip_network')
        return True
        
    def set_allowed_ips(self, allowed_ips):
        self.allowed_ips = allowed_ips
        if self.debug:
            self.print_config_list('allowed_ips')
        return True
        
    def set_endpoint_ip(self, endpoint_ip):
        self.endpoint_ip = endpoint_ip
        if self.debug:
            self.print_config_string('endpoint_ip')
        return True
        
    def set_endpoint_port(self, endpoint_port):
        self.endpoint_port = endpoint_port
        if self.debug:
            self.print_config_string('endpoint_port')
        return True

    def set_endpoint_public_key(self, endpoint_public_key):
        self.endpoint_public_key = endpoint_public_key
        if self.debug:
            self.print_config_string('endpoint_public_key')
        return True

    def set_private_key(self, private_key):
        self.private_key = private_key
        if self.debug:
            self.print_config_string('private_key')
        return True

    def set_public_key(self, public_key):
        self.public_key = public_key
        if self.debug:
            self.print_config_string('public_key')
        return True

    def set_dns_server(self, dns_server):
        self.dns_server = dns_server
        if self.debug:
            self.print_config_string('dns_server')
        return True

    def set_persistent_keepalive(self, persistent_keepalive):
        self.persistent_keepalive = persistent_keepalive
        if self.debug:
            self.print_config_string('persistent_keepalive')
        return True

    def set_peer_config(self, peer_config):
        self.peer_config = peer_config
        if self.debug:
            self.print_config_list('peer_config')
        return True

    def set_client_config(self, client_config):
        self.client_config = client_config
        if self.debug:
            self.print_config_list('client_config')
        return True

    def print_config_string(self, attribute):
        """prints a configuration string"""
        if hasattr(self, attribute):
            if getattr(self, attribute) is not None:
                description = self.attribute_index[attribute]
                value = getattr(self, attribute)
                print("%-32s %s" % (description, value))
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

    def print_config(self):
        """prints all server configuration"""
        print_attributes = ['name', 'private_key', 'public_key', 'ip_address', 'allowed_ips', 'endpoint_ip', 'dns_server', 'persistent_keepalive', 'endpoint_port', 'endpoint_public_key', 'peer_config']
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

    def dump_config(self):
        """dumps all config as json"""
        #build data_dump
        if not self.generate_config():
            print("Client configuration is invalid")
            return False
        data_dump = None
        for attribute in self.attribute_index:
            if hasattr(self, attribute):
                if getattr(self, attribute) is not None:
                    if self.debug:
                        print(f"Configuration attribute '{attribute}' read")
                    if data_dump is None:
                        data_dump = {attribute : getattr(self, attribute)}
                    else:
                        data_dump.update({attribute : getattr(self, attribute)})
                else:
                    if self.debug:
                        print(f"Configuration attribute '{attribute}' is empty")
            else:
                if self.debug:
                    print(f"Configuration attribute '{attribute}' not set")
        return data_dump

    def read_config(self, data_dump, debug = True):
        """reads json data dump to memory"""
        #check for debug setting
        if hasattr(self, 'debug') and getattr(self, 'debug') is not None:
            debug = self.debug
        #clear current config
        if debug:
            print("Clearing current configuration")
        for name in data_dump:
            if debug:
                print(f"Setting attribute '{name}' to None")
            getattr(self, 'set_' + name)(None)
        #load config
        if debug:
            print(f"Loading config")
        for name in data_dump:
            if debug:
                print(f"Setting attribute {name} to '{data_dump.get(name)}'")
            getattr(self, 'set_' + name)(data_dump.get(name))

    def generate_config(self, generate_keys = False):
        """Function to rebuild all config"""
        if generate_keys:
            if not self.generate_keys():
                print("Failed to generate new keys")
                return False
        if not self.generate_client_config():
            print("Failed to generate new client configuration")
            return False
        return True

    def generate_peer_config(self):
        """Generates the peer configuration to be added to the wireguard server"""
        #check that required attributes are set
        if (not hasattr(self, 'ip_address')) or self.ip_address is None:
            print("Client IP address is not set")
            return False
        elif (not hasattr(self, 'name')) or self.name is None:
            print("Client name is not set")
            return False
        elif (not hasattr(self, 'public_key')) or self.name is None:
            print("Public key is not set")
            return False
        allowed_ips = self.ip_address + '/32'
        config = ["#" + self.name]
        config.append('[Peer]')
        if (hasattr(self, 'persistent_keepalive')) and (self.persistent_keepalive is not None):
            config.append('PersistentKeepalive = ' + self.persistent_keepalive)
        config.append('PublicKey = ' + self.public_key)
        config.append('AllowedIPs = ' + allowed_ips)
        self.set_peer_config(config)
        return True

    def generate_client_config(self):
        """Generates the client configuration that will be used by the peer"""
        #check that the required attributes are set
        if self.generate_peer_config() is False:
            print("Failed to generate valid configuration")
            return False
        required_attributes = ['ip_address', 'endpoint_public_key', 'endpoint_ip', 'endpoint_port', 'allowed_ips']
        for attribute in required_attributes:
            if self.debug:
                print(f"Checking for attribute '{attribute}'")
            if (not hasattr(self, attribute)) or (getattr(self, attribute) is None):
                print(f"Failed to find required attribute '{attribute}'")
                return False
        #generate config
        if (hasattr(self, 'private_key')) and (self.private_key is not None):
            private_key = self.private_key
        else:
            private_key = '<UNKNOWN>'
        config = ['#Client configuration for ' + self.name]
        config.append('[Interface]')
        config.append('PrivateKey = ' + private_key)
        config.append('Address = ' + self.ip_address)
        if (hasattr(self, 'dns_server')) and (self.dns_server is not None):
            config.append('DNS = ' + self.dns_server)
        elif self.debug:
            print("DNS server not set")
        config.append('#Peer configuration for server ' + self.endpoint_ip)
        config.append('[Peer]')
        config.append('Endpoint = ' + self.endpoint_ip + ':' + self.endpoint_port)
        config.append('PublicKey = ' + self.endpoint_public_key)
        ipstr = 'AllowedIPs = '
        for ip in self.allowed_ips:
            ipstr += ip + ', '
        ipstr = ipstr[:-2]
        config.append(ipstr)
        if (hasattr(self, 'persistent_keepalive')) and (self.persistent_keepalive is not None):
            config.append('PersistentKeepalive = ' + self.persistent_keepalive)
        elif self.debug:
            print("Persistent Keepalive not set")
        self.set_client_config(config)
        return True

    def print_client_config(self):
        """Prints current client configuration"""
        if self.generate_client_config():
            for line in self.client_config:
                print(line)
        else:
            return False
        return True
