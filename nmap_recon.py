#!/usr/bin/env python3
"""
Automated Red Teaming Toolset - Nmap Recon Analyzer
====================================================
CLI berbasis Python yang mengotomatisasi pengintaian (reconnaissance)
dengan membaca hasil pemindaian Nmap (XML) dan menggunakan LLM API (Groq)
untuk menyimpulkan celah keamanan serta CVE yang mungkin terkait.

Author: betzq
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] Modul 'requests' belum terpasang. Jalankan: pip install -r requirements.txt")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("[!] Modul 'python-dotenv' belum terpasang. Jalankan: pip install -r requirements.txt")
    sys.exit(1)

# Muat variabel lingkungan dari file .env
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"


def parse_nmap_xml(xml_path):
    """
    Ekstrak port terbuka, nama layanan, dan versi dari hasil scan Nmap XML.
    Mengembalikan list of dict: [{ip, ports:[{port, protocol, service, product, version, extinfo}]}]
    """
    if not os.path.exists(xml_path):
        print(f"[!] File tidak ditemukan: {xml_path}")
        sys.exit(1)

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] Gagal mem-parse file XML: {e}")
        sys.exit(1)

    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr")

        ports = []
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = port.get("portid")
            protocol = port.get("protocol")

            service = port.find("service")
            service_name = service.get("name") if service is not None else "unknown"
            product = service.get("product") if service is not None else ""
            version = service.get("version") if service is not None else ""
            extrainfo = service.get("extrainfo") if service is not None else ""

            ports.append({
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
            })

        if ports:
            hosts.append({"ip": ip, "ports": ports})

    return hosts


def build_prompt(hosts):
    """
    Merakit data hasil scan menjadi prompt teks sistematis untuk Groq API.
    """
    lines = [
        "Anda adalah seorang konsultan keamanan siber (Red Team) senior.",
        "Tugas Anda menganalisis hasil pemindaian Nmap dan menyimpulkan potensi kerentanan keamanan",
        "beserta CVE yang mungkin terkait berdasarkan versi layanan yang terdeteksi.",
        "",
        "========================================================================",
        "HASIL PEMINDAAN NMAP (Port Terbuka, Layanan, dan Versi)",
        "========================================================================",
    ]

    for host in hosts:
        lines.append(f"\n[Host] {host['ip']}")
        for p in host["ports"]:
            info = f"  - Port {p['port']}/{p['protocol']} | {p['service']}"
            if p["product"]:
                info += f" | {p['product']}"
            if p["version"]:
                info += f" {p['version']}"
            if p["extrainfo"]:
                info += f" ({p['extrainfo']})"
            lines.append(info)

    lines.extend(
        [
            "",
            "========================================================================",
            "INSTRUKSI ANALISIS",
            "========================================================================",
            "Tolong berikan laporan dalam format Markdown dengan hal-hal berikut:",
            "",
            "1. Daftar layanan yang kemungkinan rentan berdasarkan versi layanan.",
            "2. CVE yang kemungkinan besar terkait (jika versi layanan dikenal).",
            "3. Penjelasan singkat risiko setiap temuan.",
            "4. Rekomendasi mitigasi singkat untuk setiap port/layanan.",
            "5. Tingkat risiko (Low / Medium / High / Critical) untuk setiap temuan.",
            "",
            "Tuliskan hasil analisis dalam bahasa Indonesia yang profesional, objektif,",
            "dan mudah dipahami oleh tim keamanan.",
        ]
    )

    return "\n".join(lines)


def query_groq(prompt):
    """
    Mengirim prompt ke Groq API dan mengembalikan respons teks analisis.
    """
    if not GROQ_API_KEY:
        print("[!] GROQ_API_KEY belum diatur. Buat file .env dan isi GROQ_API_KEY=kunci_anda")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "Anda adalah asisten keamanan siber yang ahli dalam analisis kerentanan jaringan dan reconnaissance.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 2000,
    }

    print("[*] Mengirim permintaan ke Groq API... mohon tunggu")
    try:
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
    except requests.RequestException as e:
        print(f"[!] Kesalahan jaringan saat memanggil Groq API: {e}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"[!] Gagal memanggil Groq API: {resp.status_code} - {resp.text}")
        sys.exit(1)

    data = resp.json()
    return data["choices"][0]["message"]["content"]


def main():
    parser = argparse.ArgumentParser(
        description="Automated Red Teaming Toolset - Analisis hasil scan Nmap dengan AI (Groq)"
    )
    parser.add_argument(
        "nmap_xml",
        help="Path ke file hasil scan Nmap dalam format XML (.xml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="recon_report.md",
        help="File output laporan analisis (default: recon_report.md)",
    )
    args = parser.parse_args()

    print(f"[*] Membaca file Nmap XML: {args.nmap_xml}")
    hosts = parse_nmap_xml(args.nmap_xml)

    if not hosts:
        print("[!] Tidak ada host dengan port terbuka yang ditemukan.")
        sys.exit(0)

    print(f"[*] Ditemukan {len(hosts)} host dengan port terbuka. Merakit prompt...")
    prompt = build_prompt(hosts)

    report = query_groq(prompt)

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")
    print(f"[+] Laporan analisis berhasil disimpan ke: {output_path}")


if __name__ == "__main__":
    main()
