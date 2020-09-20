# Wireguard router project

 Manages servers and users
 
 
 Automatically creates config files and generates user configs
 
 Automatically generates wireguard server and interface configuration
 
 Starts/stops wireguard interfaces
 
 Creates port forwarding rules

# Install wiregard on debian

    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt update
    apt install wireguard
    apt install libmnl-dev libelf-dev linux-headers-$(uname -r) build-essential pkg-config
    modprobe wireguard

# Install wireguard on Gentoo

	##unmask package
	echo "virtual/wireguard ~amd64" > /etc/portage/package.keywords/wireguard
	echo "net-vpn/wireguard-modules ~amd64 " >> /etc/portage/package.keywords/wireguard
	echo "net-vpn/wireguard-tools ~amd64 " >> /etc/portage/package.keywords/wireguard

	##emerge
	emerge resolvconf net-vpn/wireguard-tools net-vpn/wireguard-modules

	##add modules to be loaded
	echo 'modules="wireguard"' >> /etc/conf.d/modules
	modprobe wireguard

# Kernel rules for Gentoo

	[*] Networking support > 
		Networking Options --->
		[*] TCP/IP Networking
		<M> IP: Foo (IP protocols) over UDP
			[*] Network packet filtering framework (Netfilter) --->
				[*] Advanced netfilter configuration
					Core Netfilter Configuration --->
						<M> Netfilter connection tracking support
						<*> Netfilter Xtables support
						<M> nfmark target and match support
						<M> "CONNMARK" target support
						<M> "comment" match support
						<M> "hashlimit" match support
					IP: Netfilter Configuration --->
						<M> raw table support (required for NOTRACK/TRACE)
	[*] Cryptographic API --->
		[*] Cryptographic algorithm manager
		[M] Parallel crypro engine

# OpenRC Start file

	#!/sbin/openrc-run
	depend() {
		need net
		want dns
	}

	start() {
		wg-quick up {interface_name}
	}

	stop() {
		wg-quick down {interface_name}
	}

	restart() {
		wg-quick down {interface_name}
		wg-quick up {interface_name}
	}	

	status() {
		wg show {interface_name}
	}
	
	name="Wireguard client"

### TODO:

* check connected peers
* set interface autostart
