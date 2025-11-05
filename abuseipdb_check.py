#!/usr/bin/env python3
"""
abuseipdb_check.py

Uso:
  - Crear un archivo .env con:
        ABUSEIPDB_API_KEY=tu_api_key_aqui

  - Usar un archivo de IPs:
        python3 abuseipdb_check.py --input ips.txt --out reporte.csv

  - O dejar --input vacío: buscará archivos .csv en el directorio actual y ofrecerá un menú.
  Requisitos:
  pip install requests tqdm
"""
import argparse
import csv
import os
import requests
from dotenv import load_dotenv

# Diccionario de categorías de AbuseIPDB
CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}

API_URL = "https://api.abuseipdb.com/api/v2/check"

def load_api_key():
    load_dotenv()
    return os.getenv("ABUSEIPDB_API_KEY")

def query_ip(ip, api_key, max_age=90):
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age),
        "verbose": True  # necesario para ver reports detallados
    }
    response = requests.get(API_URL, headers=headers, params=params)
    response.raise_for_status()
    return response.json()["data"]

def parse_categories(reports):
    motivos = []
    for r in reports:
        for c in r.get("categories", []):
            motivos.append(CATEGORY_MAP.get(c, f"Desconocido({c})"))
    # evitar duplicados y ordenar
    return ", ".join(sorted(set(motivos)))

def suggest_csv_file():
    csv_files = [f for f in os.listdir(".") if f.endswith(".csv")]
    if not csv_files:
        print("⚠️ No se encontraron archivos CSV en el directorio actual.")
        return None
    print("📂 Archivos CSV disponibles:")
    for i, f in enumerate(csv_files, 1):
        print(f"{i}. {f}")
    choice = input("Seleccione un archivo por número: ")
    try:
        return csv_files[int(choice)-1]
    except (ValueError, IndexError):
        print("❌ Selección inválida.")
        return None

def main():
    parser = argparse.ArgumentParser(description="Consulta IPs en AbuseIPDB")
    parser.add_argument("--input", help="Archivo CSV con lista de IPs (una por línea)")
    parser.add_argument("--output", default="reporte_abuseipdb.csv", help="Archivo CSV de salida")
    args = parser.parse_args()

    # Selección de input
    input_file = args.input
    if not input_file:
        input_file = suggest_csv_file()
        if not input_file:
            return

    # Leer IPs
    with open(input_file, newline="") as f:
        reader = csv.reader(f)
        ips = [row[0].strip() for row in reader if row]

    api_key = load_api_key()
    if not api_key:
        print("❌ No se encontró ABUSEIPDB_API_KEY en .env")
        return

    results = []
    for ip in ips:
        print(f"🔎 Consultando {ip} ...")
        try:
            data = query_ip(ip, api_key)
            if data["abuseConfidenceScore"] > 0 and data.get("reports"):
                motivos = parse_categories(data["reports"])
                results.append({
                    "ip": ip,
                    "score": data["abuseConfidenceScore"],
                    "total_reports": data["totalReports"],
                    "last_reported": data.get("lastReportedAt", ""),
                    "motivos": motivos
                })
                print(f"➡️ {ip} reportada ({data['abuseConfidenceScore']} pts, motivos: {motivos})")
            else:
                print(f"✅ {ip} sin reportes.")
        except Exception as e:
            print(f"❌ Error con {ip}: {e}")

    # Guardar CSV
    if results:
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\n📄 Reporte guardado en {args.output}")
    else:
        print("\n✅ Ninguna IP reportada, no se generó CSV.")

if __name__ == "__main__":
    main()
