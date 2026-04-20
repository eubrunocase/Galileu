import sys
import os
import datetime
from scapy.all import rdpcap, TCP, IP
from fpdf import FPDF

def get_protocol_label(packet):
    if packet.haslayer(TCP):
        payload = bytes(packet[TCP].payload)
        methods = [b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS", b"HTTP/1."]
        if any(payload.startswith(m) for m in methods):
            return "HTTP"
        return "TCP"
    return "Outro"

def create_pdf_report(pcap_file):
    output_pdf = os.path.splitext(pcap_file)[0] + "_relatorio.pdf"
    
    try:
        print(f"[*] Analisando pacotes de: {pcap_file}")
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Erro ao ler PCAP: {e}")
        return

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Projeto Galileu - Relatório de Tráfego", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)

    pdf.set_fill_color(200, 220, 255)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(20, 10, "Pacote", 1, 0, 'C', True)
    pdf.cell(30, 10, "Protocolo", 1, 0, 'C', True)
    pdf.cell(90, 10, "Fluxo (Origem -> Destino)", 1, 0, 'C', True)
    pdf.cell(50, 10, "Tamanho", 1, 1, 'C', True)

    pdf.set_font("Arial", size=9)
    for i, pkt in enumerate(packets):
        if pkt.haslayer(IP):
            label = get_protocol_label(pkt)
            flow = f"{pkt[IP].src} -> {pkt[IP].dst}"
            pdf.cell(20, 8, str(i + 1), 1)
            pdf.cell(30, 8, label, 1)
            pdf.cell(90, 8, flow, 1)
            pdf.cell(50, 8, f"{len(pkt)} bytes", 1, 1)

    pdf.output(output_pdf)
    print(f"[+] Relatório gerado com sucesso: {output_pdf}")

if __name__ == "__main__":
    default_pcap = "guardian_log.pcap"
    
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    elif os.path.exists(default_pcap):
        pcap_path = default_pcap
    else:
        pcap_path = input("Arquivo padrão não encontrado. Arraste o arquivo .pcap aqui: ").strip().replace("'", "").replace('"', "")

    if os.path.exists(pcap_path):
        create_pdf_report(pcap_path)
    else:
        print(f"[!] Arquivo não encontrado: {pcap_path}")