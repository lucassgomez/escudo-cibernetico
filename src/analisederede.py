import scapy.all as scapy
from scapy.layers.inet import IP, TCP

def sniff_packets(interface):
    """Captura pacotes de rede e analisa pacotes TCP/IP."""
    scapy.sniff(iface=interface, prn=process_packet, store=False)

def process_packet(packet):
    """Processa cada pacote capturado para análise."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Pacote de {ip_src} para {ip_dst}")
        
        if packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"Portas TCP: {tcp_src_port} -> {tcp_dst_port}")
            analyze_tcp_packet(packet)

def analyze_tcp_packet(packet):
    """Realiza análise básica do pacote TCP."""
    if packet[TCP].flags == "S":  # SYN
        print("Tentativa de conexão detectada (SYN)")
    elif packet[TCP].flags == "A":  # ACK
        print("Pacote ACK detectado")
    elif packet[TCP].flags == "F":  # FIN
        print("Conexão terminada (FIN)")
