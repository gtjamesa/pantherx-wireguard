#!/bin/bash

# Other vars
OS=$(awk -F= '/^ID/{print $2}' /etc/os-release | sed 's/"//g')
CLIENT_ORIGINAL_IP=$(curl -s ipecho.net/plain)
DEFAULT_INTERFACE=$(ip route list table main default | grep -oP 'dev (\K\w+)(?= )')
GATEWAY_IP=$(ip route list table main default | grep -oP 'via (\K[0-9\.]+)(?= )')
LAN_IP=$(ip -brief address show "${DEFAULT_INTERFACE}" | grep -oP '(\K[0-9\.]+)(?=/)' | head -1)
PUBLIC_VPN_IP=""
VPN_SERVER_IP=""
VPN_CLIENT_IP=""
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
  wg

  echo ''
  echo -e "${LIGHTBLUE}Checking that the VPN is active...${NC}"
  sleep 5

  IP_NOW=$(curl -s ipecho.net/plain)

  echo -e "Original IP: ${GREEN}${CLIENT_ORIGINAL_IP}${NC}"
  echo -e "Current IP: ${GREEN}${IP_NOW}${NC}"
  echo ''
}

enable_ip_forwarding() {
  sed 's/^#net\.ipv4\.ip_forward=[01]/net.ipv4.ip_forward=1/' -i.bak /etc/sysctl.conf
  sudo sysctl -p
}

# All non-private IP addresses will be routed through the VPN
# https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/
# Allowed IPs: 0.0.0.0/0
# Disallowed IPs: 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 240.0.0.0/4, fc00::/7, fe80::/10
write_wireguard_config() {
  cat << EOT > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${VPN_CLIENT_IP}/32
ListenPort = 51820
DNS = 1.1.1.1 1.0.0.1

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = ip rule add table 200 from ${LAN_IP}
PostUp = ip route add table 200 default via ${GATEWAY_IP}
PostUp = iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
PostUp = iptables -t nat -A POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PreDown = ip rule delete table 200 from ${LAN_IP}
PreDown = ip route delete table 200 default via ${GATEWAY_IP}
PreDown = iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE
PreDown = iptables -t nat -D POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${PUBLIC_VPN_IP}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
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

  CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/private.key)
  CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/public.key)
}

install_packages() {
  # Add Debian back-ports repository
  if [[ "${OS}" == "debian" ]]; then
    echo 'deb http://deb.debian.org/debian buster-backports main' > /etc/apt/sources.list.d/buster-backports.list
  fi

  # not installing ufw here
  # may need openresolv if the resolvconf binary isn't installed
  apt update -y \
    && apt install -y wireguard tcpdump htop vim wget curl

  if [[ -z $(which resolvconf) ]]; then
    apt install -y openresolv
  fi
}

prompt_complete_server() {
  echo ''
  echo -e "${LIGHTBLUE}-----------------${NC}"
  echo -e "${LIGHTBLUE}  Server Config${NC}"
  echo -e "${LIGHTBLUE}-----------------${NC}"
  echo ''
  echo -e "${LIGHTBLUE}Enter the following public key on the server${NC}"
  echo ''

  echo -e "Client Public Key: ${GREEN}${CLIENT_PUBLIC_KEY}${NC}"
  echo ''

  # Wait for user to answer
  ask "Have you added the key onto the server?"

  if [[ $? -eq 0 ]]; then
    echo "Continuing anyway ¯\_(^.^)_/¯"
  fi
}

begin_installation() {
  install_packages
  create_wireguard_keys
  write_wireguard_config
  enable_ip_forwarding
  prompt_complete_server
  start_wireguard
}

# Ensure user is root
if [[ $UID -ne 0 ]]; then
  echo -e "${RED}Exiting: Script must be run as root${NC}"
  exit 0
fi

#  echo -e "Public VPN IP: ${GREEN}${VPN_IP}${NC}"
#  echo -e "Internal Server IP: ${GREEN}${VPN_SERVER_IP}${NC}"
#  echo -e "Internal Client IP: ${GREEN}${VPN_CLIENT_IP}${NC}"
#  echo -e "Server Public Key: ${GREEN}${SERVER_PUBLIC_KEY}${NC}"

echo ''
echo -e "${LIGHTBLUE}------------------${NC}"
echo -e "${LIGHTBLUE}VPN Client Setup${NC}"
echo -e "${LIGHTBLUE}------------------${NC}"
echo ''
echo -e "${LIGHTBLUE}We need some information from the server script to continue...${NC}"
echo ''

#####
# Get info
#####
echo -e "${GREEN}Public VPN IP: ${NC}"
read -r PUBLIC_VPN_IP

echo -e "${GREEN}Internal Server IP: ${NC}"
read -r VPN_SERVER_IP

echo -e "${GREEN}Internal Client IP: ${NC}"
read -r VPN_CLIENT_IP

echo -e "${GREEN}Server Public Key: ${NC}"
read -r SERVER_PUBLIC_KEY
#####

echo ''
echo -e "Public VPN IP: ${GREEN}${PUBLIC_VPN_IP}${NC}"
echo -e "Interface: ${GREEN}${DEFAULT_INTERFACE}${NC}"
echo -e "Internal Server IP: ${GREEN}${VPN_SERVER_IP}${NC}"
echo -e "Internal Client IP: ${GREEN}${VPN_CLIENT_IP}${NC}"
echo -e "Server Public Key: ${GREEN}${SERVER_PUBLIC_KEY}${NC}"
echo ''
echo ''
echo 'This will install a Wireguard VPN client. Are you sure you want to to this? (y/n) '
echo ''
read -p 'Answer: ' reply

if [[ $reply =~ ^[Yy]$ ]]; then
  begin_installation
fi
