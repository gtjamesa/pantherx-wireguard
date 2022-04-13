#!/bin/bash

# Set the following variables if you wish to modify the configuration from the default
# The VPN server is for internal routing, and is not seen to the outside world
# Ensure that the server IP is "x.x.x.1"
# The hotspot (VPN client) will automatically be configured to "x.x.x.2"
VPN_SERVER_IP="10.13.13.1"
#
# Do not modify anything further
#

# Other vars
OS=$(awk -F= '/^ID/{print $2}' /etc/os-release | sed 's/"//g')
VPN_IP=$(curl -s ipecho.net/plain)
DEFAULT_INTERFACE=$(ip route list table main default | grep -oP 'dev (\K\w+)(?= )')
VPN_CLIENT_IP=$(echo "$VPN_SERVER_IP" | sed 's/\.1$/.2/')
SERVER_PRIVATE_KEY=""
SERVER_PUBLIC_KEY=""
CLIENT_PRIVATE_KEY=""
CLIENT_PUBLIC_KEY=""

# Colours
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
LIGHTBLUE='\033[1;34m'

ask() {
  while true; do
    read -p "$1 (y/n) " -r
    REPLY=${REPLY:-"y"}
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      return 1
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
      return 0
    fi
  done
}

add_client() {
  sudo wg set wg0 peer "${CLIENT_PUBLIC_KEY}" allowed-ips "${VPN_CLIENT_IP}"

  # Verify peer was added
  wg

  # Restart Wireguard on the VPS server to save and update configuration
  wg-quick down wg0 && wg-quick up wg0
}

start_wireguard() {
  echo -e "${LIGHTBLUE}Starting Wireguard...${NC}"
  wg-quick up wg0
}

configure_fw() {
  # Allow SSH and Wireguard
  # SSH is allowed to all IPs by default because we are using the cloud providers firewall on the outside
  ufw allow 22/tcp
  ufw allow 51820/udp

  # Allow Helium traffic
  ufw allow 44158/tcp
  ufw allow to "${VPN_CLIENT_IP}" port 44158 proto tcp
  #  ufw allow to 172.31.0.0/16 port 44158 proto tcp

  # Allow IPv4 forwarding between network interfaces
  ufw route allow in on wg0 out on "${DEFAULT_INTERFACE}"
  ufw route allow in on wg0 out on wg0
  ufw route allow in on "${DEFAULT_INTERFACE}" out on wg0

  # Restart firewall
  ufw enable
  service ufw restart
  ufw status
}

enable_ip_forwarding() {
  sed 's/^#net\.ipv4\.ip_forward=[01]/net.ipv4.ip_forward=1/' -i.bak /etc/sysctl.conf
  sed 's/^#net\/ipv4\/ip_forward=[01]/net\/ipv4\/ip_forward=1/' -i.bak /etc/ufw/sysctl.conf
  sudo sysctl -p
}

write_wireguard_config() {
  cat << EOT > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = ${VPN_SERVER_IP}/32
ListenPort = 51820
SaveConfig = true

PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostUp = iptables -A FORWARD -i ${DEFAULT_INTERFACE} -o wg0 -p tcp --syn --dport 44158 -m conntrack --ctstate NEW -j ACCEPT
PostUp = iptables -A FORWARD -i ${DEFAULT_INTERFACE} -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = iptables -t nat -A PREROUTING -i ${DEFAULT_INTERFACE} -p tcp --dport 44158 -j DNAT --to-destination ${VPN_CLIENT_IP}
PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${DEFAULT_INTERFACE} -o wg0 -p tcp --syn --dport 44158 -m conntrack --ctstate NEW -j ACCEPT
PostDown = iptables -D FORWARD -i ${DEFAULT_INTERFACE} -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -t nat -D PREROUTING -i ${DEFAULT_INTERFACE} -p tcp --dport 44158 -j DNAT --to-destination ${VPN_CLIENT_IP}
EOT

  chmod 0600 /etc/wireguard/wg0.conf
}

create_wireguard_keys() {
  mkdir -p /etc/wireguard

  # Generate private key
  wg genkey | sudo tee /etc/wireguard/private.key

  # Restrict permissions
  chmod 0600 /etc/wireguard/private.key

  # Generate public key from the private key
  sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

  SERVER_PRIVATE_KEY=$(cat /etc/wireguard/private.key)
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/public.key)
}

install_packages() {
  apt update -y \
    && apt install -y wireguard ufw tcpdump htop vim wget curl
}

prompt_client_installation() {
  echo ''
  echo -e "${LIGHTBLUE}-----------------${NC}"
  echo -e "${LIGHTBLUE}  Client Config${NC}"
  echo -e "${LIGHTBLUE}-----------------${NC}"
  echo ''
  echo -e "${LIGHTBLUE}You will now need to run the client-setup.sh on the hotspot${NC}"
  echo -e "${LIGHTBLUE}Enter the following information on the hotspot when prompted${NC}"
  echo ''

  echo -e "Public VPN IP: ${GREEN}${VPN_IP}${NC}"
  echo -e "Internal Server IP: ${GREEN}${VPN_SERVER_IP}${NC}"
  echo -e "Internal Client IP: ${GREEN}${VPN_CLIENT_IP}${NC}"
  echo -e "Server Public Key: ${GREEN}${SERVER_PUBLIC_KEY}${NC}"
  echo ''

  echo -e "${LIGHTBLUE}Once the client has been configured, it will output a public key. Enter it below to continue.${NC}"

  # Get the client public key
  read -p 'Client public key: ' CPK
  CLIENT_PUBLIC_KEY="$CPK"

  add_client
}

begin_installation() {
  install_packages
  create_wireguard_keys
  write_wireguard_config
  enable_ip_forwarding
  configure_fw
  start_wireguard
  prompt_client_installation
}

# Ensure user is root
if [[ $UID -ne 0 ]]; then
  echo -e "${RED}Exiting: Script must be run as root${NC}"
  exit 0
fi

echo ''
echo -e "${LIGHTBLUE}------------------${NC}"
echo -e "${LIGHTBLUE}VPN Server Setup${NC}"
echo -e "${LIGHTBLUE}------------------${NC}"
echo ''
echo -e "VPN IP: ${GREEN}${VPN_IP}${NC}"
echo -e "Interface: ${GREEN}${DEFAULT_INTERFACE}${NC}"
echo -e "Internal Server IP: ${GREEN}${VPN_SERVER_IP}${NC}"
echo -e "Internal Client IP: ${GREEN}${VPN_CLIENT_IP}${NC}"
echo ''
echo ''
echo 'This will install a Wireguard VPN server. Are you sure you want to to this? (y/n) '
echo ''
read -p 'Answer: ' reply

if [[ $reply =~ ^[Yy]$ ]]; then
  begin_installation
fi
