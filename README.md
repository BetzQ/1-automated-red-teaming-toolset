# Automated Red Teaming Toolset

CLI berbasis Python yang mengotomatisasi pengintaian (reconnaissance) dengan membaca hasil pemindaian Nmap (XML) dan menggunakan LLM API (Groq) untuk menyimpulkan celah keamanan serta CVE yang mungkin terkait berdasarkan versi layanan.

## Deskripsi

Toolset ini membantu tim Red Team dalam menganalisis hasil scan Nmap secara otomatis. Alih-alih membaca hasil scan secara manual dan mencari CVE satu per satu, skrip ini:

1. Membaca file `nmap_scan.xml` hasil pemindaian Nmap.
2. Mengekstrak port terbuka, nama layanan, produk, dan versinya.
3. Merakit data tersebut menjadi prompt terstruktur.
4. Mengirim prompt ke Groq API (LLaMA) untuk analisis kerentanan.
5. Menyimpan hasil analisis ke file `recon_report.md`.

## Arsitektur Alur Kerja

```
file nmap_scan.xml
        |
        v
+---------------------+
|  nmap_recon.py      |
|  (xml.etree.ElementTree)  |
+---------------------+
        |
        v
+---------------------+
|  Prompt Terstruktur |
+---------------------+
        |
        v
+---------------------+      HTTPS POST      +---------------------+
|  Groq API (LLaMA)   | <------------------> |  requests / dotenv  |
+---------------------+                      +---------------------+
        |
        v
+---------------------+
|  recon_report.md    |
+---------------------+
```

## Cara Instalasi

### 1. Clone repositori

```bash
git clone https://github.com/betzq/1-automated-red-teaming-toolset.git
cd 1-automated-red-teaming-toolset
```

### 2. Buat virtual environment (direkomendasikan)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependensi

```bash
pip install -r requirements.txt
```

### 4. Siapkan API Key Groq

Salin file contoh environment:

```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Buka file `.env` dan isi `GROQ_API_KEY` dengan API key Anda:

```
GROQ_API_KEY=gsk_ubah_dengan_api_key_anda
```

Dapatkan API key gratis di [https://console.groq.com/](https://console.groq.com/).

## Contoh Penggunaan CLI

### Jalankan dengan file scan bawaan (contoh)

```bash
python nmap_recon.py sample_nmap_scan.xml
```

### Jalankan dengan file scan hasil Anda sendiri

```bash
# Pastikan file hasil scan Nmap dalam format XML, misalnya:
nmap -sV -oX hasil_scan.xml 192.168.1.0/24

# Lalu jalankan skrip:
python nmap_recon.py hasil_scan.xml -o recon_report.md
```

### Opsi CLI

| Argumen | Keterangan |
|---------|------------|
| `nmap_xml` | Path ke file hasil scan Nmap format XML (wajib) |
| `-o, --output` | Nama file output laporan (default: `recon_report.md`) |

## Contoh Output (`recon_report.md`)

Laporan yang dihasilkan akan berisi:
- Daftar layanan yang mungkin rentan berdasarkan versi.
- CVE yang kemungkinan besar terkait.
- Penjelasan risiko singkat.
- Rekomendasi mitigasi.
- Tingkat risiko (Low / Medium / High / Critical).

## Struktur Repositori

```
1-automated-red-teaming-toolset/
├── nmap_recon.py          # Skrip CLI utama
├── requirements.txt       # Dependensi Python
├── .env.example           # Contoh variabel lingkungan
├── .env                   # (Buat sendiri, jangan di-commit)
├── sample_nmap_scan.xml   # File contoh hasil scan Nmap
├── recon_report.md        # (Dihasilkan otomatis setelah menjalankan skrip)
└── README.md              # Dokumentasi ini
```

## Catatan Keamanan

- Jangan pernah commit file `.env` yang berisi API key asli ke GitHub. Tambahkan `.env` ke `.gitignore`.
- Tool ini untuk tujuan edukasi dan pengujian keamanan pada sistem yang Anda miliki atau memiliki izin untuk mengujinya.
