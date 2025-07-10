#!/bin/bash
set -e # Keluar jika ada perintah yang gagal

# Periksa apakah python3 terinstal
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 tidak ditemukan. Mohon instal python3."
    exit 1
fi

# Buat virtual environment jika belum ada
if [ ! -d "venv" ]; then
    echo "Membuat virtual environment..."
    python3 -m venv venv
fi

# Aktifkan virtual environment
echo "Mengaktifkan virtual environment..."
source venv/bin/activate

# Instal dependensi dari requirements.txt
echo "Menginstal dependensi dari requirements.txt..."
pip install -r requirements.txt

# Jalankan skrip Python utama
echo "Menjalankan Octra Client..."
python kazmight.py
