#!/usr/bin/env python3
import ipaddress
import subprocess
import os
import json
import pdb
from WgServer import WgServer


class ObjectGenerator(object):
    """Helps to create various types of objects"""
    attribute_index = {
        'config_dir' : 'Configuration root directory',
        'config_file' : 'File to load and save server configuration to',
        'wg_servers' : 'Wireguard Server Objects',
    }
    def __init__(self, config_file = '/etc/wireguard/conf-dump.json', mode = 'interactive', debug = False):
        self.debug = debug
        self.set_config_file(config_file)
        #Go to menu if option is interactive
        if mode == 'interactive':
            print("Press q at any time to exit")
            print("Press m to return to the last menu you were in")
            print("Press r to return to a higher menu level")
            if not self.load_config():
                self.get_config_location()
            self.main_menu()

    def get_data(self, default = None):
        """Standardize gathering user input"""
        if (hasattr(self, 'prompt')) and (self.prompt is not None):
            prompt = self.prompt
        else:
            prompt = ''
        if default is not None:
            prompt += '[' + str(default) + ']> '
        else:
            prompt += '> '
        usr = input(prompt)
        
        if not usr:
            return default
        if usr == '!DEBUG':
            pdb.set_trace()
        if usr.lower() == 'm':
            if (hasattr(self, 'location')) and (self.location is not None):
                if self.location == 'get_config':
                    self.get_config_location()
                elif self.location == 'main':
                    self.main_menu()
                elif (not hasattr(self, 'server')) or (self.server is None):
                    print(f"Cannot access location '{self.location}' without selecting a server first")
                    return False
                elif self.location == 'ports':
                    self.manage_server_ports()
                elif self.location == 'configuration':
                    self.manage_server_configuration()
                elif self.location == 'manage':
                    self.manage_server()
                else:
                    print("Invalid location")
                    return False
            else:
                print("Location not specified")
                return False
        if usr.lower() == 'r':
            if (hasattr(self, 'location')) and (self.location is not None):
                if self.location == 'main':
                    print("Already at main menu")
                    return False
                elif self.location == 'server_generator':
                    self.main_menu()
                elif self.location == 'manage':
                    self.main_menu()
                elif (not hasattr(self, 'server')) or (self.server is None):
                    print(f"Cannot access server management menu without selecting a server first")
                    return False
                elif (self.location == 'ports') or (self.location == 'configuration'):
                    self.manage_server()
        if usr.lower() == 'q':
            print("exiting")
            exit()
        print(f"\n\n")
        return usr.lower()
    
    def set_wg_servers(self, servers):
        self.wg_servers = servers
        
    def set_server(self, server_name):
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            if server_name in self.wg_servers:
                try:
                    self.server = self.wg_servers[server_name]
                except:
                    print(f"Failed to load server '{server_name}'")
                    return False
            else:
                print(f"Server '{server_name}' not found")
                return False
        else:
            print("No servers loaded")
            return False
        return True

    def set_config_dir(self, config_dir):
        self.config_dir = config_dir
        if self.debug:
            print(f"Configuration directory set to '{config_dir}'")

    def set_config_file(self, config_file):
        self.config_file = config_file
        if self.debug:
            print(f"Configuration file set to '{config_file}'")

    def main_menu(self):
        """Menu for interactive interface"""
        self.location = 'main'
        self.prompt = '{main}'
        if (not hasattr(self, 'config_dir')) or (self.config_dir is None):
            self.generate_self()
        while True:
            print(f"\n\nOptions: ")
            print("[g] Generate wireguard server")
            print("[p] Print Servers")
            print("[c] Configure servers")
            print("[s] Save configuration")
            print("[d] Delete server")
            choice = self.get_data('option')
            if choice == 'g':
                self.generate_wg_server()
                continue
            elif choice == 'p':
                self.print_servers()
                continue
            elif choice == 'c':
                if not self.get_server_choice():
                    print("No wireguard servers found")
                else:
                    self.manage_server(server_name = self.server)
            elif choice == 's':
                self.save_config()
                continue
            elif choice == 'd':
                self.del_server()
                continue
            else:
                print("Invalid input")
                
    def get_config_location(self):
        """Gets the config file location"""
        self.location = 'get_config'
        while True:
            print(f"\n\nOptions:")
            print("[q]: Quit")
            print("[l]: Load configuration")
            print("[g]: Generate new configuration")
            usr = self.get_data('option')
            if usr == 'l':
                print("Enter configuration path")
                config_file = self.get_data('config path')
                self.set_config_file(config_file)
                if not self.load_config():
                    print("Failed to load configuration")
                else:
                    print(f"Loaded configuation from file '{config_file}'")
            if usr == 'g':
                print("Generating new configuration")
                if self.generate_self():
                    break
    
    def get_server_choice(self):
        """Interactively sets the server choice"""
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            print("Enter the number of the server you want to manage")
            i = 0
            names = []
            for server in self.wg_servers:
                print(f"{i} : {server}")
                names.append(server)
                i += 1
            while True:
                usr = self.get_data('server')
                if usr == 'server':
                    continue
                try:
                    selection = int(usr)
                except:
                    print("You must enter a number")
                    continue
                if (selection >= 0) and (selection < len(self.wg_servers)):
                    server_name = names[selection]
                    self.server = server_name
                    return server_name
                else:
                    print("Invalid selection")
                    continue
        return False
        
    def print_servers(self):
        """Prints out the servers"""
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            print("================")
            for server in self.wg_servers.values():
                print(server.name)
                print(f"    Network: {server.network}")
                print(f"    IP Address: {server.ip_address}")
                print(f"    Public Key: {server.public_key}")
                print(f"    Endpoint: {server.server_ip}:{server.listen_port}")
                server.print_peers()
                server.print_ports()
                print("================")
        else:
            print("No servers found")

    def manage_server(self, server_name = None):
        """Manage wireguard servers"""
        self.location = 'manage'
        if server_name is not None:
            self.set_server(server_name)
        if (not hasattr(self, 'server')) or (self.server is None):
            print("Failed to get server information")
            return False
        server = self.server
        self.prompt = '{' + server.name + '}'
        while True:
            print(f"\n\nOptions:")
            print("[p] Print config")
            print("[e] Edit Configuration")
            print("[x] Export client config")
            print("[a] Add peer")
            print("[i] Import peer with public key")
            print("[d] Delete peer")
            print("[s] Start server interface")
            print("[k] Stop server interface")
            print("[l] Restart server interface")
            print("[f] Port forwarding")
            usr = self.get_data('option')
            if usr == 'p':
                server.print_config()
                server.print_peers()
                server.print_ports()
                continue
            elif usr == 'e':
                if not self.manage_server_configuration():
                    print("Failed to edit server configuration")
                continue
            elif usr == 'x':
                if (hasattr(server, 'peers')) and (server.peers is not None):
                    print("Enter peer name: ")
                    usr = self.get_data('peer name')
                    if usr != 'peer name':
                        server.print_client_config(usr)
                        continue
                else:
                    print("No peers found")
                    continue
            elif usr == 'a':
                print("Enter peer name: ")
                usr = self.get_data('peer name')
                if (usr == 'peer name') or (not server.check_peer_name(usr)):
                    print(f"Invalid peer name '{usr}'")
                    continue
                peer_name = usr
                print("Enter peer ip: ")
                usr = self.get_data('ip address')
                if not server.check_peer_ip(usr):
                    print(f"Invalid peer IP '{usr}'")
                    continue
                peer_ip = usr
                if not server.add_peer(peer_name, peer_ip):
                    print("Failed to add peer")
                    continue
                elif not self.update_user_conf(peer_name):
                    print("Failed to update server configuration")
                    continue
                else:
                    print("Saved peer configuration file. Interface may need to be reloaded")
                    self.save_config()
                continue
            elif usr == 'i':
                print("Enter peer name: ")
                usr = self.get_data('peer name')
                if (usr == 'peer name') or (not server.check_peer_name(usr)):
                    print(f"Invalid peer name '{usr}'")
                    continue
                peer_name = usr
                print("Enter peer ip: ")
                usr = self.get_data('ip address')
                if not server.check_peer_ip(usr):
                    print(f"Invalid peer IP '{usr}'")
                    continue
                peer_ip = usr
                usr = self.get_data('public key')
                if not server.check_peer_key(usr):
                    print(f"Invalid user public key '{usr}'")
                    continue
                public_key = usr
                if not server.add_peer(peer_name = peer_name, peer_ip = peer_ip, public_key = usr):
                    print("Failed to add peer")
                    continue
                elif not self.update_user_conf(peer_name):
                    print("Failed to update server configuration")
                    continue
                else:
                    print("Saved peer configuration file. Interface may need to be reloaded")
                    self.save_config()
                continue
            elif usr == 'd':
                if (hasattr(server, 'peers')) and (server.peers is not None):
                    print("Enter peer name: ")
                    usr = self.get_data('peer name')
                    if (usr == 'peer name') or (usr not in server.peers):
                        print(f"Invalid peer name '{usr}'")
                        continue
                    peer_name = usr
                    if not server.del_peer(peer_name):
                        print(f"Failed to delete peer '{peer_name}'")
                        continue
                    elif server.write_interface_config():
                        self.save_config()
                        print("Peer deleted and configuration filed deleted. Interface may need to be reloaded")
                    continue
                else:
                    print("No peers found")
                    continue
            elif usr == 's':
                if not self.start_server():
                    continue
                print("Started server interface")
                continue
            elif usr == 'k':
                if not self.stop_server():
                    continue
                print("Stopped server interface")
                continue
            elif usr == 'l':
                if not self.stop_server():
                    continue
                if not self.start_server():
                    continue
                print("Restarted the server interface")
                continue
            elif usr == 'f':
                if not self.manage_server_ports(): 
                    print("Failed to manage server port configuration")
                continue
            else:
                print("Invalid input")
        else:
            print("No servers found")
            return False

    def update_user_conf(self, name, server_name = None,):
        """Adds a config file to a wireguard server"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        if name not in server.peers:
            print(f"User by name '{name}' not found in server '{server.name}'")
            return False
        if not server.write_peer_config(name):
            print("Failed to write peer configuration")
        peer_config_file = server.config_dir + '/' + server.name + '-' + name + '.conf'
        cmd = subprocess.run(['wg', 'addconf', server.name, peer_config_file], stdout = subprocess.PIPE)
        if cmd.returncode != 0:
            print("Failed to update server configuration")
            return False
        else:
            try:
                if stdout is not None:
                    print(stdout)
            except:
                print("Configuration added to server")
            return True
            
    def stop_server(self, server_name = None):
        """Stops a wireguard server"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        cmd = subprocess.run(['ifdown', server.name], stdout = subprocess.PIPE)
        if cmd.returncode != 0:
            print("Failed to stop server interface")
            return False
        else:
            return True
            
    def start_server(self, server_name = None):
        """starts a wireguard server"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        cmd = subprocess.run(['ifup', server.name], stdout = subprocess.PIPE)
        if cmd.returncode != 0:
            print("Failed to start server interface")
            return False
        else:
            return True

    def manage_server_ports(self, server_name = None):
        """Manages a server's port configuration interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        self.prompt = '{' + server.name + '-port management}'
        self.location = 'ports'
        while True:
            print("Options:")
            print("[p] Print port rules")
            print("[a] Add port forwarding rule")
            print("[d] Delete port forwarding rule")
            usr = self.get_data('port configuration')
            if usr == 'p':
                server.print_ports()
                continue
            elif usr == 'a':
                if not self.add_server_port_rule():
                    print("Failed to add port rule")
                    continue
            elif usr == 'd':
                if not self.del_server_port_rule():
                    print("Failed to delete port rule")
                    continue
            else:
                print("Invalid input")
                             
    def add_server_port_rule(self, server_name = None):
        """Adds a server port rule interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        if (not hasattr(server, 'peers')) or (server.peers is None):
            print("You need to add a peer to forward a port")
            return False
        while True:
            valid_name = True
            print("Enter rule name")
            usr = self.get_data('rule name')
            if usr == 'rule name':
                continue
            #Check that rule name is valid
            if (hasattr(server, 'ports')) and (server.ports is not None):
                if usr in server.ports:
                    print("A rule by that name already exists")
                    valid_name = False
            if valid_name:
                name = usr
                break
        while True:
            print("Enter protocol (udp/tcp/both)")
            usr = self.get_data('protocol')
            if usr == 'protocol':
                continue
            #check that protocol is valid
            if (usr != 'tcp') and (usr != 'udp') and (usr != 'both'):
                print("Invalid protocol")
                continue
            protocol = usr
            break
        while True:
            print("Enter outbound port")
            usr = self.get_data('wan port')
            if usr == 'wan port':
                continue
            #check that port and protocol are valid
            if not self.check_port(port = usr, protocol = protocol):
                print("Invalid port or protocol specified")
                continue
            wan_port = usr
            break
        while True:
            print("Enter destination port")
            usr = self.get_data(wan_port)
            if not self.check_port(usr):
                print("Invalid port specified")
                continue
            lan_port = usr
            break
        while True:
            print("Enter destination IP or client name")
            usr = self.get_data('destination ip')
            if usr == 'destination ip':
                continue
            #check if user specified
            if (hasattr(server, 'peers')) and (server.peers is not None) and (usr in server.peers):
                peer = server.peers.get(usr)
                lan_ip = peer.ip_address
                break
            elif (hasattr(server, 'peers')) and (server.peers is not None):
                valid_ip = False
                for peer in server.peers.values():
                    if peer.ip_address == usr:
                        valid_ip = True
                        break
                if valid_ip:
                    lan_ip = usr
                    break
                else:
                    print("No peer found with that IP address")
                    continue
            else:
                print("Invalid LAN IP")
                continue
        if not server.add_port(name = name, protocol =  protocol, lan_port = lan_port, lan_ip = lan_ip, wan_port = wan_port):
            print("Failed to add port rule to server")
            return False
        elif not self.stop_server():
            print("Failed to stop the server")
            return False
        elif not server.write_interface_config():
            print("Failed to generate new configuration with that port rule")
            return False
        elif not self.start_server():
            print("Failed to start the server")
            return False    
        else:
            return self.save_config()
    
    def del_server_port_rule(self, server_name = None):
        """Deletes a server port rule interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        if (not hasattr(server, 'ports')) or (server.ports is None):
            print("No ports configured")
            return False
        while True:
            print("Enter the rule name to be deleted")
            usr = self.get_data('rule name')
            if usr == 'rule name':
                continue
            if usr in server.ports:
                break
            else:
                print(f"Rule '{usr}' not found")
                return False
        if not server.del_port(usr):
            print("Failed to delete port rule")
            return False
        elif not self.stop_server():
            print("Failed to stop the server")
            return False
        elif not server.write_interface_config():
            print("Failed to generate new configuration with that port rule")
            return False
        elif not self.start_server():
            print("Failed to start the server")
            return False
        else:
            return self.save_config()
                
    def manage_server_configuration(self, server_name = None):
        """Manage various server configuration parameters interactively"""
        self.location = 'configuration'
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        self.prompt = '{' + server.name + '-configuration}'
        while True:
            print("Options:")
            print("[d] Set DNS server")
            print("[k] Set persistent keepalive interval")
            print("[w] WAN interface")
            print("[g] Gateway mode")
            usr = self.get_data('option')
            if usr == 'd':
                self.manage_server_dns()
                continue
            elif usr == 'k':
                self.manage_server_keepalive()
                continue
            elif usr == 'w':
                self.manage_server_interface()
                continue
            elif usr == 'g':
                self.manage_server_gateway()
            else:
                print("Invalid input")

    def manage_server_dns(self, server_name = None):
        """Manage server DNS configuration interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        while True:
            print("Enter DNS Server IP:")
            print("Enter d to disable this option")
            if (hasattr(server, 'dns_server')) and (server.dns_server is not None):
                usr = self.get_data(server.dns_server)
            else:
                usr = self.get_data('1.1.1.1')
            if usr == 'd':
                if not server.set_dns_server(None):
                    print("Failed to disable default server dns option")
                    return False
                else:
                    print("Disabled default dns server configuration")
                    return True
            try:
                ip_interface = ipaddress.IPv4Interface(usr)
                ip_address = ip_interface.ip
            except:
                print("Invalid IP address")
                return False
            if not server.set_dns_server(usr):
                print("Failed to set DNS server")
                return False
            else:
                print(f"Set DNS server to {usr}")
                return self.save_config()
        
    def manage_server_gateway(self, server_name = None):
        """Manage server gateway configuration interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        while True:
            print("Would you like to enable the gateway?")
            print("Options:")
            print("[y] Enable the gateway")
            print("[n] Disable the gateway")
            if (hasattr(server, 'gateway')) and (server.gateway is not None):
                usr = self.get_data(server.gateway)
            else:
                usr = self.get_data('y')
            if usr == 'y' or usr == 'n':
                if not server.set_gateway(usr):
                    print("Failed to set the gateway mode")
                    return False
                elif not self.stop_server():
                    print("Failed to stop the server")
                    return False
                elif not server.write_interface_config():
                    print("Failed to write the new gateway setting")
                    return False
                elif not self.start_server():
                    print("Failed to start the server")
                    return False
                else:
                    return self.save_config()
                       
    def manage_server_keepalive(self, server_name = None):
        """Manage server persistent keepalive interactivelely"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        while True:
            print("Enter persistent keepalive interval:")
            print("Enter 0 to disable it")
            if (hasattr(server, 'persistent_keepalive')) and (server.persistent_keepalive is not None):
                usr = self.get_data(server.persistent_keepalive)
            else:
                usr = self.get_data('25')
            if usr == '0':
                if not server.set_persistent_keepalive(None):
                    print("Failed to disable default server persistent keepalive option")
                    return False
                else:
                    print("Disabled default persistent keepalive configuration")
                    return True
            try:
                persistent_keepalive = int(usr)
            except:
                print("You must enter a number")
                return False
            if not server.set_persistent_keepalive(usr):
                print("Failed to set persistent keepalive interval")
                return False
            else:
                print(f"Set persistent keepalive interval to '{usr}'")
                return self.save_config()
        
    def manage_server_interface(self, server_name = None):
        """Manage server interface settings interactively"""
        if server_name is not None:
            self.set_server(server_name)
        server = self.server
        while True:
            print("Select WAN interface")
            if (hasattr(server, 'wan_if')) and (server.wan_if is not None):
                wan_if = self.get_wan_if(prompt = server.wan_if)
            else:
                wan_if = self.get_wan_if()
            if not wan_if:
                print("Failed get WAN interface")
                return False
            if not server.set_wan_if(wan_if):
                print("Failed to set WAN interface")
                return False
            elif not self.stop_server():
                print("Failed to stop the server")
                return False
            elif not server.write_interface_config():
                print("Failed to write new interface setting")
                return False
            elif not self.start_server():
                print("Failed to start the server")
                return False
            else:
                return self.save_config()
            
    def check_name(self, name, new = False):
        """Checks that the interface name is not already in use"""
        #Check that interface doesn't already exist if creating a new one
        if new:
            try:
                interfaces = os.listdir('/sys/class/net/')
                if (name == interfaces) or (name in interfaces):
                    print("An interface by that name already exists")
                    return False
            except:
                print("Failed to get interfaces")
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            for server in self.wg_servers.values():
                if server.name == name:
                    print("Server name already in use")
                    return False
        return True

    def check_network(self, interface_address = None, ip_address = None, network = None):
        """Checks that the ip/network does not confligct with existing servers"""
        #Generate network and ip from interface
        if interface_address is not None:
            #Fails if interface is formatted improperly
            try:
                ip_interface = ipaddress.IPv4Interface(interface_address)
                network = ipaddress.IPv4Network(ip_interface.network)
                ip_address = ip_interface.ip
            except:
                print(f"Invalid interface address '{interface_address}' specified")
                return False
        elif (ip_address is not None) and (network is not None):
            #Set them if they are passed as arguments
            ip_address = ipaddress.IPv4Address(ip_address)
            network = ipaddress.IPv4Network(network)
        else:
            print("Invalid parameters specified")
            return False
        #check that ip is not broadcast or network ip
        if ip_address not in network.hosts():
            print(f"IP '{ip_address}' is not in wireguard network '{network}'")
            return False
            if '/32' in str(network):
                print("Invalid subnet size")
                return False
            if str(network).startswith('169.254.'):
                print("Invalid network")
                return False
        try:
            interfaces = os.listdir('/sys/class/net/')
            for interface in interfaces:
                interface_read = os.popen('ip a s ' + interface).read()
                try:
                    host_interface_ip = interface_read.split("inet ")[1].split("/")[0]
                except IndexError:
                    continue
                host_interface_network = interface_read.split("inet ")[1].split("/")[1].split(" ")[0]
                host_interface = ipaddress.IPv4Interface(host_interface_ip + '/' + host_interface_network)
                host_network = host_interface.network
                host_ip_address = host_interface.ip
                #continue if bad interface
                if str(host_network).startswith('169.254.'):
                    continue
                if ip_address in host_network.hosts():
                    print(f"IP Address '{ip_address}' already exists in host network '{host_network}' on interface '{interface}'")
                    return False
                if host_ip_address in network.hosts():
                    print(f"Host IP address '{host_ip_address}' already exists in network '{network}', invalid configuration'")
                    return False
        except:
            print("Unable to find network interfaces")
            return False
        #check for ip conflicts
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            for server in self.wg_servers.values():
                server_ip_interface = ipaddress.IPv4Interface(server.ip_address)
                server_ip_network = ipaddress.IPv4Network(server_ip_interface.network)
                if (server_ip_interface.ip in network.hosts()) or (ip_address in server_ip_network.hosts()):
                    print(f"IP network '{network}' conflicts with network '{server.network}' already used by wireguard server '{server.name}'")
                    return False
        return True

    def check_port(self, port, protocol = 'udp'):
        """Checks that the port is not already in use by another wireguard server or port forward"""
        if not self.check_port_number(port):
            print("Invalid port number specified")
            return False
        if (protocol != 'tcp') and (protocol != 'udp') and (protocol != 'both'):
            print("Invalid protocol specified")
            return False
        if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
            for server in self.wg_servers.values():
                #check if port conflicts with server port
                if ((protocol == 'udp') or (protocol == 'both')) and (server.listen_port == port):
                    print(f"Listen port already in use by wireguard server {server.name}")
                    return False
                #check forwarded ports as well
                if (hasattr(server, 'ports')) and (server.ports is not None):
                    for p in server.ports.values():
                        if (p.get('wan_port') == port) and ((p.get('protocol') == protocol) or (p.get('protocol') == 'both')):
                            print(f"Listen port already in use by port forward name '{p.get('name')}' in server {server.name}")
                            return False
        return True
        
    def check_port_number(self, port):
        """Checks if a port number is valid"""
        try:
            int(port)
        except:
            print("Port must be a number")
            return False
        if (int(port) < 1) or (int(port) > 65535):
            print("Invalid Port specified")
            return False
        return True

    def load_server(self, data_dump):
        """Loads a server from a json data dump"""
        if self.debug:
            print(data_dump)
        name = data_dump.get('name')
        ip_address = data_dump.get('ip_address')
        network = data_dump.get('network')
        listen_port = data_dump.get('listen_port')
        server = WgServer(data_dump = data_dump)
        #add server
        if (hasattr(self, 'wg_servers')) and (getattr(self, 'wg_servers') is not None) and self.wg_servers:
            self.wg_servers.update({name: server})
        else:
            self.set_wg_servers({name: server})
        return True

    def del_server(self):
        """Deletes a server and its configuration"""
        #Check that server exists
        if (hasattr(self, 'wg_servers')) and (getattr(self, 'wg_servers') is not None) and self.wg_servers:
            print("Listing servers")
            i = 0
            names = []
            for server in self.wg_servers:
                print(f"{i} : {server}")
                names.append(server)
                i += 1
            print("Enter the number of the server you want to delete")
            while True:
                usr = self.get_data()
                #fails if input is not a number
                try:
                    selection = int(usr)
                except:
                    print("You must enter a number")
                    continue
                if (selection >= 0) and (selection < len(self.wg_servers)):
                    break
                else:
                    print("Invalid selection")
            server_name = names[selection]
            #Check that server by that name exists(should always be true)
            if server_name in self.wg_servers:
                if self.debug:
                    print(f"Deleting wireguard server '{server_name}'")
                server = self.wg_servers[server_name]
                server.delete_interface_config()
                server.delete_server_config()
                server.delete_keys()
                #delete peers if they exist
                if (hasattr(server, 'peers')) and (getattr(server, 'peers') is not None) and server.peers:
                    peer_names = []
                    for peer in server.peers:
                        peer_names.append(peer)
                    for peer in peer_names:
                        server.del_peer(peer)
                    
                #try to delete config dir, fails gracefully
                try:
                    os.rmdir(self.config_dir + '/' + server_name)
                except:
                    print("Failed to remove server configuration directory")
                del self.wg_servers[server_name]
                self.save_config()
        else:
            print("No servers found")
            return False
        return True

    def save_config(self):
        """Saves configuration to a file"""
        if self.debug:
            print(f"Saving configuration to '{self.config_file}'")
        #build config dict
        for attribute in self.attribute_index:
            if hasattr(self, attribute):
                if getattr(self, attribute) is not None:
                    if attribute == 'wg_servers':
                        if self.debug:
                            print("Reading servers")
                        server_config = None
                        server_data = getattr(self, attribute)
                        for server in server_data.values():
                            server_dump = server.dump_config()
                            if self.debug:
                                print(f"Server data for {server.name}: {server_dump}")
                            if server_config is None:
                                server_config = {server.name : server_dump}
                            else:
                                server_config.update({server.name : server_dump})
                        config_entry = {attribute: server_config}
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
                print(f"Configuration attribute '{attribute}' is not set")
        #move existing config
        if os.path.isfile(self.config_file):
            old_config_file = self.config_file + '.old'
            if self.debug:
                print(f"Server configuration file already exists, moving to '{old_config_file}'")
            try:
                os.rename(self.config_file, old_config_file)
            except OSError:
                print("Failed to move file")
                return False
        #Write configuration dump
        if self.debug:
            print(f"Writing configuration to '{self.config_file}'")
        try:
            with open(self.config_file, 'a') as file:
                json.dump(config, file)
        except PermissionError:
            print("Unable to write file. Permission denied")
            return False
        #protect server configuration file
        if self.debug:
            print(f"Changing the file permissions of '{self.config_file}' to '600'")
        try:
            os.chmod(self.config_file, 0o600)
        except PermissionError:
            print("Unable to change file permissions. Permission denied")
            return False
        return config

    def load_config(self):
        """Loads configuration from a file"""
        if self.debug:
            print(f"Loading configuration from file '{self.config_file}'")
        #check that file exists
        if not os.path.isfile(self.config_file):
            print(f"Configuration file '{self.config_file}' not found")
            return False
        #read configuration
        if self.debug:
            print("File exists, reading")
        try:
            with open(self.config_file, 'r') as file:
                config = json.load(file)
        except PermissionError:
            print("Permission denied")
            return False
        #load configuration
        if self.debug:
            print("Loading configuration into memory")
            print(config)
        if True:
            for name in config:
                if (name == 'wg_servers') and (config.get('wg_servers') is not None):
                    if self.debug:
                        print("Reading servers")
                    servers = config.get('wg_servers')
                    for server in servers.values():
                        self.load_server(server)
                else:
                    getattr(self, 'set_' + name)(config.get(name))
        return True
            
    def get_wan_if(self, prompt = 'interface'):
        """Prompts for getting the WAN interface"""
        try:
            interfaces = os.listdir('/sys/class/net/')
        except:
            print("Unable to find network interfaces")
            return False
        print("Select a wan interface for this network")
        i = 0
        for interface in interfaces:
            print(f"{i}: {interface}")
            if interface == prompt:
                prompt = str(i)
            i += 1
        while True:
            usr = self.get_data(prompt)
            if usr == 'interface':
                print("Invalid input")
                continue
            if usr == 'd':
                return usr
            try:
                selection = int(usr)
            except:
               print("You must enter a number")
               continue
            if (selection < 0) or (selection >= len(interfaces)):
                print("Invalid selection")
                continue
            else:
                break
        wan_if = interfaces[selection]
        return wan_if

    def generate_self(self):
        """Generates the base configuration for this object"""
        print("Enter the config dir")
        print("This is where all of the configuration files will be saved.")
        print("This is the global config folder and interface folders will be created under this one")
        config_dir = None
        while config_dir is None:
            config_dir = self.get_data('/etc/wireguard')
            if not os.path.isdir(config_dir):
                print("Directory not found, would you like to create it?")
                usr = self.get_data('y')
                if usr == 'y':
                    try:
                        os.mkdir(config_dir)
                    except OSError:
                        print("Unable to create configuration directory")
                        return False
        self.set_config_dir(config_dir)
        self.set_config_file(config_dir + '/conf-dump.json')
        self.save_config()
        return True

    def generate_wg_server(self):
        """Wireguard server creation wiz"""
        self.location = 'server_generator'
        self.prompt = '{server generator}'
        print("Creating wireguard server")
        print("Enter the interface name for the new wireguard server")
        print("You should choose a name like 'wg0' or 'vpn0'")
        print("Can be short and descriptive like: 'vps-wg0'")
        valid = False
        while not valid:
            name = self.get_data('wg0')
            valid = self.check_name(name = name, new = True)
        if self.debug:
            print(f"name read as '{name}'")
        print("Enter the interface address for the new wireguard server")
        print("ex. 10.0.0.1/24, 192.168.1.1/24, NOT 10.0.0.1 255.255.255.0 or 192.168.1.1 255.255.255.0")
        valid = False
        while not valid:
            interface_address = self.get_data('172.16.0.1/24')
            valid = self.check_network(interface_address = interface_address)
            if valid:
                ip_interface = ipaddress.IPv4Interface(interface_address)
                ip_address = str(ip_interface.ip)
                network = str(ip_interface.network)
                netmask = str(ip_interface.netmask)
        if self.debug:
            print(f"IP address read as '{ip_address}'")
            print(f"Network read as '{network}'")
            print(f"Network mask read as '{netmask}'")
        print("Enter the server listen port")
        print("Must be from 1-65535")
        print("51820 is common for wireguard")
        valid = False
        while not valid:
            valid = True
            listen_port = self.get_data('51820')
            valid = self.check_port(listen_port)
        if self.debug:
            print(f"Listen port read as '{listen_port}'")
        print("Should this server act as a gateway?")
        print("If this is enabled, nat rules will be added and a gateway interface will need to be selected")
        gateway = self.get_data('y')
        wan_if = self.get_wan_if()
        if self.debug:
            print(f"Wan interface set to '{wan_if}'")
        config_dir = self.config_dir + '/' + name
        server = WgServer(
            name = name,
            ip_address = ip_address,
            network = network,
            netmask = netmask,
            listen_port = listen_port,
            config_dir = config_dir,
            wan_if = wan_if,
            gateway = gateway,
            debug = self.debug,
        )
        if not server.error:
            if gateway != 'y':
                server.set_wan_if 
            if (hasattr(self, 'wg_servers')) and (self.wg_servers is not None):
                self.wg_servers.update({name: server})
            else:
                self.wg_servers = {name: server}
            self.save_config()
        else:
            print("Failed to create wireguard server")
            print("Try running with debugging enabled")
            return False
        return True
