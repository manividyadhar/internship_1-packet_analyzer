"""
Network Packet Analyzer
A cross-platform packet sniffer tool for educational purposes
Captures and analyzes network packets displaying IP addresses, protocols, and payload data
"""

import socket
import struct
import textwrap
import sys
import platform
import argparse
from datetime import datetime
import json
import os

class PacketAnalyzer:
    """Main class for network packet analysis"""
    
    def __init__(self, interface=None, output_file=None, filter_protocol=None):
        self.interface = interface
        self.output_file = output_file
        self.filter_protocol = filter_protocol
        self.packet_count = 0
        self.packets_data = []
        
    def create_socket(self):
        """Create appropriate socket based on operating system"""
        os_type = platform.system()
        
        try:
            if os_type == "Windows":
                # Windows requires IPPROTO_IP for raw sockets
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((self.get_local_ip(), 0))
                # Enable promiscuous mode on Windows
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print(f"[+] Socket created successfully on Windows")
                print(f"[+] Listening on: {self.get_local_ip()}")
                
            else:  # Linux/Unix
                # Linux requires different socket configuration
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                print(f"[+] Socket created successfully on Linux")
                if self.interface:
                    print(f"[+] Listening on interface: {self.interface}")
                    
            return sock
            
        except PermissionError:
            print("[!] Error: Administrator/Root privileges required!")
            print("[!] On Windows: Run as Administrator")
            print("[!] On Linux: Run with sudo")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error creating socket: {e}")
            sys.exit(1)
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def start_sniffing(self, packet_limit=None):
        """Start capturing packets"""
        sock = self.create_socket()
        os_type = platform.system()
        
        print("\n" + "="*70)
        print("NETWORK PACKET ANALYZER - STARTED")
        print("="*70)
        print(f"Operating System: {os_type}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.filter_protocol:
            print(f"Protocol Filter: {self.filter_protocol.upper()}")
        if packet_limit:
            print(f"Packet Limit: {packet_limit}")
        print("="*70)
        print("\nPress Ctrl+C to stop capturing...\n")
        
        try:
            while True:
                if packet_limit and self.packet_count >= packet_limit:
                    break
                    
                raw_data, addr = sock.recvfrom(65535)
                
                # On Linux, we need to skip the ethernet header
                if os_type != "Windows":
                    # Ethernet header is 14 bytes
                    eth_header = raw_data[:14]
                    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]
                    
                    # Check if it's an IP packet (0x0800)
                    if eth_protocol != 0x0800:
                        continue
                    
                    raw_data = raw_data[14:]  # Remove ethernet header
                
                self.process_packet(raw_data)
                
        except KeyboardInterrupt:
            print("\n\n[+] Stopping packet capture...")
            self.print_statistics()
            
            # Disable promiscuous mode on Windows
            if os_type == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
            sock.close()
            
            if self.output_file:
                self.save_to_file()
            
            print("\n[+] Packet analyzer stopped successfully!")
    
    def process_packet(self, raw_data):
        """Process individual packet"""
        # Parse IP header
        ip_header = self.parse_ipv4_header(raw_data)
        
        if not ip_header:
            return
        
        # Apply protocol filter if specified
        if self.filter_protocol:
            if self.filter_protocol.upper() not in ip_header['protocol'].upper():
                return
        
        self.packet_count += 1
        
        print(f"\n{'='*70}")
        print(f"Packet #{self.packet_count} - {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
        print(f"{'='*70}")
        
        # Display IP information
        print(f"\n[IPv4 Header]")
        print(f"  Source IP      : {ip_header['src_ip']}")
        print(f"  Destination IP : {ip_header['dest_ip']}")
        print(f"  Protocol       : {ip_header['protocol']} ({ip_header['protocol_num']})")
        print(f"  TTL            : {ip_header['ttl']}")
        print(f"  Header Length  : {ip_header['header_length']} bytes")
        print(f"  Total Length   : {ip_header['total_length']} bytes")
        
        # Extract payload based on protocol
        data = raw_data[ip_header['header_length']:]
        
        # Parse transport layer protocols
        if ip_header['protocol_num'] == 6:  # TCP
            tcp_info = self.parse_tcp(data)
            self.display_tcp_info(tcp_info)
            payload = data[tcp_info['header_length']:]
            
        elif ip_header['protocol_num'] == 17:  # UDP
            udp_info = self.parse_udp(data)
            self.display_udp_info(udp_info)
            payload = data[8:]  # UDP header is 8 bytes
            
        elif ip_header['protocol_num'] == 1:  # ICMP
            icmp_info = self.parse_icmp(data)
            self.display_icmp_info(icmp_info)
            payload = data[8:]
            
        else:
            payload = data
        
        # Display payload
        if payload:
            self.display_payload(payload)
        
        # Store packet data for later export
        packet_info = {
            'number': self.packet_count,
            'timestamp': datetime.now().isoformat(),
            'ip_header': ip_header,
            'payload_size': len(payload)
        }
        self.packets_data.append(packet_info)
    
    def parse_ipv4_header(self, raw_data):
        """Parse IPv4 header"""
        try:
            # Unpack the first 20 bytes of IP header
            version_header_length = raw_data[0]
            version = version_header_length >> 4
            header_length = (version_header_length & 15) * 4
            
            ttl, protocol_num, src, dest = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
            
            protocol_map = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP',
                41: 'IPv6',
                89: 'OSPF'
            }
            
            protocol = protocol_map.get(protocol_num, f'Other ({protocol_num})')
            
            # Get total length
            total_length = struct.unpack('!H', raw_data[2:4])[0]
            
            return {
                'version': version,
                'header_length': header_length,
                'ttl': ttl,
                'protocol': protocol,
                'protocol_num': protocol_num,
                'src_ip': self.format_ipv4(src),
                'dest_ip': self.format_ipv4(dest),
                'total_length': total_length
            }
        except:
            return None
    
    def parse_tcp(self, data):
        """Parse TCP header"""
        try:
            src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
            offset = (offset_reserved_flags >> 12) * 4
            
            flag_urg = (offset_reserved_flags & 32) >> 5
            flag_ack = (offset_reserved_flags & 16) >> 4
            flag_psh = (offset_reserved_flags & 8) >> 3
            flag_rst = (offset_reserved_flags & 4) >> 2
            flag_syn = (offset_reserved_flags & 2) >> 1
            flag_fin = offset_reserved_flags & 1
            
            return {
                'src_port': src_port,
                'dest_port': dest_port,
                'sequence': sequence,
                'acknowledgment': acknowledgment,
                'header_length': offset,
                'flags': {
                    'URG': flag_urg,
                    'ACK': flag_ack,
                    'PSH': flag_psh,
                    'RST': flag_rst,
                    'SYN': flag_syn,
                    'FIN': flag_fin
                }
            }
        except:
            return None
    
    def parse_udp(self, data):
        """Parse UDP header"""
        try:
            src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
            return {
                'src_port': src_port,
                'dest_port': dest_port,
                'length': length
            }
        except:
            return None
    
    def parse_icmp(self, data):
        """Parse ICMP header"""
        try:
            icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
            
            icmp_types = {
                0: 'Echo Reply',
                3: 'Destination Unreachable',
                8: 'Echo Request',
                11: 'Time Exceeded'
            }
            
            return {
                'type': icmp_type,
                'type_name': icmp_types.get(icmp_type, 'Other'),
                'code': code,
                'checksum': checksum
            }
        except:
            return None
    
    def display_tcp_info(self, tcp_info):
        """Display TCP information"""
        if not tcp_info:
            return
            
        print(f"\n[TCP Segment]")
        print(f"  Source Port    : {tcp_info['src_port']}")
        print(f"  Dest Port      : {tcp_info['dest_port']}")
        print(f"  Sequence       : {tcp_info['sequence']}")
        print(f"  Acknowledgment : {tcp_info['acknowledgment']}")
        
        flags = tcp_info['flags']
        flag_str = ' '.join([f for f, v in flags.items() if v])
        print(f"  Flags          : {flag_str if flag_str else 'None'}")
    
    def display_udp_info(self, udp_info):
        """Display UDP information"""
        if not udp_info:
            return
            
        print(f"\n[UDP Datagram]")
        print(f"  Source Port    : {udp_info['src_port']}")
        print(f"  Dest Port      : {udp_info['dest_port']}")
        print(f"  Length         : {udp_info['length']}")
    
    def display_icmp_info(self, icmp_info):
        """Display ICMP information"""
        if not icmp_info:
            return
            
        print(f"\n[ICMP Packet]")
        print(f"  Type           : {icmp_info['type']} ({icmp_info['type_name']})")
        print(f"  Code           : {icmp_info['code']}")
        print(f"  Checksum       : {icmp_info['checksum']}")
    
    def display_payload(self, payload, max_bytes=100):
        """Display packet payload"""
        if len(payload) == 0:
            return
            
        print(f"\n[Payload Data] ({len(payload)} bytes)")
        
        # Try to decode as text
        try:
            text = payload.decode('utf-8', errors='ignore')
            if text.isprintable():
                print(f"  Text Data:")
                # Wrap text to 60 characters
                wrapped = textwrap.fill(text[:200], width=60)
                for line in wrapped.split('\n'):
                    print(f"    {line}")
                if len(text) > 200:
                    print(f"    ... ({len(text) - 200} more characters)")
        except:
            pass
        
        # Show hex dump of first few bytes
        print(f"\n  Hex Dump (first {min(max_bytes, len(payload))} bytes):")
        hex_data = payload[:max_bytes]
        self.display_hex_dump(hex_data)
    
    def display_hex_dump(self, data):
        """Display hex dump of data"""
        for i in range(0, len(data), 16):
            hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            print(f"    {i:04x}  {hex_str:<48}  {ascii_str}")
    
    def format_ipv4(self, addr):
        """Format IPv4 address from bytes"""
        return '.'.join(map(str, addr))
    
    def print_statistics(self):
        """Print capture statistics"""
        print("\n" + "="*70)
        print("CAPTURE STATISTICS")
        print("="*70)
        print(f"Total Packets Captured: {self.packet_count}")
        print("="*70)
    
    def save_to_file(self):
        """Save captured packets to JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    'capture_info': {
                        'timestamp': datetime.now().isoformat(),
                        'total_packets': self.packet_count,
                        'os': platform.system()
                    },
                    'packets': self.packets_data
                }, f, indent=2)
            print(f"\n[+] Packet data saved to: {self.output_file}")
        except Exception as e:
            print(f"\n[!] Error saving to file: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Network Packet Analyzer - Educational Tool',
        epilog='Example: python packet_analyzer.py -c 50 -o packets.json -f TCP'
    )
    
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-o', '--output', type=str, help='Output file for packet data (JSON)')
    parser.add_argument('-f', '--filter', type=str, choices=['TCP', 'UDP', 'ICMP'], 
                       help='Filter by protocol')
    parser.add_argument('-i', '--interface', type=str, help='Network interface (Linux only)')
    
    args = parser.parse_args()
    
    # Display banner
    print("\n" + "="*70)
    print(" "*15 + "NETWORK PACKET ANALYZER")
    print("="*70)
    
    
    # Check privileges
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("\n[!] Please run as Administrator!")
                sys.exit(1)
        except:
            pass
    else:
        if os.geteuid() != 0:
            print("\n[!] Please run with sudo privileges!")
            sys.exit(1)
    
    # Create analyzer instance
    analyzer = PacketAnalyzer(
        interface=args.interface,
        output_file=args.output,
        filter_protocol=args.filter
    )
    
    # Start sniffing
    analyzer.start_sniffing(packet_limit=args.count)


if __name__ == "__main__":
    main()
