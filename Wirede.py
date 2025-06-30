import re
import csv
from collections import Counter
import os

def parse_text_log(log_file_path):
    """Analisa logs de texto gerados a partir do Wireshark."""
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)'
    
    ip_counter = Counter()
    errors = []
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                match = re.match(log_pattern, line.strip())
                if match:
                    timestamp, level, message = match.groups()
                    ip_matches = re.findall(ip_pattern, message)
                    src_ip = ip_matches[0] if ip_matches else "N/A"
                    dst_ip = ip_matches[1] if len(ip_matches) > 1 else "N/A"
                    
                    ip_counter[src_ip] += 1
                    ip_counter[dst_ip] += 1
                    if level == "ERROR" or "retransmission" in message.lower() or "connection refused" in message.lower():
                        errors.append({
                            'timestamp': timestamp,
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'message': message
                        })
        return ip_counter, errors
    except FileNotFoundError:
        print(f"Arquivo {log_file_path} não encontrado")
        return None, None

def parse_csv_log(log_file_path):
    """Analisa logs em CSV exportados do Wireshark."""
    ip_counter = Counter()
    errors = []
    
    try:
        with open(log_file_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                src_ip = row.get('source_ip', 'N/A')
                dst_ip = row.get('destination_ip', 'N/A')
                ip_counter[src_ip] += 1
                ip_counter[dst_ip] += 1
                if row['level'] == "ERROR" or "retransmission" in row['info'].lower() or "connection refused" in row['info'].lower():
                    errors.append({
                        'timestamp': row['timestamp'],
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'message': row['info']
                    })
        return ip_counter, errors
    except FileNotFoundError:
        print(f"Arquivo {log_file_path} não encontrado")
        return None, None

def generate_report(ip_counter, errors, output_csv="wireshark_report.csv"):
    """Gera relatório em CSV | abra no Google Planilhas."""
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Relatório de Monitoramento de Rede - Wireshark"])
        writer.writerow([])
        
        writer.writerow(["Resumo de IPs"])
        writer.writerow(["IP", "Ocorrências"])
        for ip, count in ip_counter.items():
            if ip != "N/A":
                writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Erros de Rede"])
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Mensagem"])
        for error in errors:
            writer.writerow([error['timestamp'], error['source_ip'], error['destination_ip'], error['message']])
    
    print(f"Relatório gerado em {output_csv}")

def main():
    text_log_file = "wireshark.log"  # Caminho do arquivo de texto
    csv_log_file = "wireshark.csv"   # Caminho do arquivo CSV
    output_csv = "wireshark_report.csv"  # Relatório de saída

    if os.path.exists(text_log_file):
        print("Processando arquivo de texto...")
        ip_counter, errors = parse_text_log(text_log_file)
        if ip_counter and errors is not None:
            generate_report(ip_counter, errors, output_csv)
    elif os.path.exists(csv_log_file):
        print("Processando arquivo CSV...")
        ip_counter, errors = parse_csv_log(csv_log_file)
        if ip_counter and errors is not None:
            generate_report(ip_counter, errors, output_csv)
    else:
        print("Nenhum arquivo de log encontrado. ")

if __name__ == "__main__":
    main()