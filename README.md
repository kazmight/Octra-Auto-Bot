## 🚀 Octra Pre Client CLI Wallet - Multi-Akun (v0.1.0) 🚀

Selamat datang di Octra CLI Wallet, sebuah command-line interface (CLI) yang kuat dan menarik untuk mengelola aset Octra Anda langsung dari terminal. Dirancang untuk efisiensi dan kemudahan penggunaan, wallet ini mendukung multi-akun, memungkinkan Anda beralih di antara dompet dengan lancar, serta melakukan transaksi publik dan privat.
Proyek ini dibangun untuk pengujian di jaringan testnet Octra dan terus diperbarui. Selalu pantau perubahan dan gunakan dengan hati-hati untuk dana non-signifikan.


## ✨ Fitur Utama
Antarmuka Pengguna CLI Interaktif: Desain berbasis teks yang jernih dan responsif.
Dukungan Multi-Akun: Muat beberapa dompet dari wallet.json atau tambahkan secara manual di sesi berjalan.
Muat Otomatis: Deteksi dan muat akun dari wallet.json saat startup.
Transaksi Publik: Kirim dan terima OCT secara transparan di jaringan.
Transaksi Privat: Enkripsi dan dekripsi saldo untuk transfer rahasia.
Klaim Transfer Privat: Kelola transfer privat yang tertunda.
Detail Dompet Lengkap: Lihat saldo, nonce, riwayat transaksi terbaru, dan detail public key Anda.
Sesuai untuk Testnet: Dikonfigurasi untuk berinteraksi dengan node RPC Octra di https://octra.network.

## 🛠️ Instalasi & Persiapan
Ikuti langkah-langkah mudah ini untuk menjalankan Octra CLI Wallet di lingkungan Anda.

Kloning Repositori:
```Bash
git clone https://github.com/kazmight/Octra-Testnet-Bot
```
```bash
cd Octra-Testnet-Bot
```

Buat File requirements.txt:
Di dalam folder proyek, buat file bernama requirements.txt dan isi dengan dependensi berikut:
```bash
mnemonic
pycryptodomex
aiohttp
hdwallet
PyNaCl
cryptography
```
Siapkan File wallet.json (Opsional, tapi Direkomendasikan):
Untuk memuat dompet secara otomatis saat startup, buat file wallet.json di direktori proyek yang sama. Anda bisa menyimpan satu atau lebih akun di sini.

Contoh wallet.json (MULTI-AKUN):
```bash
JSON

[
  {
    "name": "Octra Main",
    "priv": "MASUKKAN_PRIVATE_KEY_BASE64_AKUN",
    "addr": "octxxxxxxxxxxxxxxxxx",
    "rpc": "https://octra.network"
  },
  {
    "name": "Octra Secondary",
    "priv": "MASUKKAN_PRIVATE_KEY_BASE64_AKUN_LAINNYA",
    "addr": "octxxxxxxxxxx",
    "rpc": "https://octra.network"
  }
]
```
PERINGATAN SANGAT PENTING: Menyimpan kunci privat dalam bentuk teks biasa di wallet.json TIDAK AMAN. File ini dapat dengan mudah diakses. Jangan gunakan ini untuk dana sungguhan. Ini hanya disarankan untuk tujuan pengujian dengan jumlah OCT yang tidak signifikan.

## 🚀 Cara Menjalankan
Kami telah menyediakan skrip bantu untuk menyederhanakan proses penyiapan dan menjalankan CLI Wallet Anda.

Berikan Izin Eksekusi:
```Bash
chmod +x run.sh
```
Jalankan Skrip:
```Bash
./run.sh
```

Skrip ini akan:
Memastikan Python 3 terinstal.
Membuat atau mengaktifkan venv (lingkungan virtual Python) untuk isolasi dependensi.
Menginstal semua pustaka dari requirements.txt.
Menjalankan kazmight.py.
Setelah Klien Berjalan:
Jika wallet.json ada, akun pertama akan dimuat dan ditampilkan.
Anda dapat menggunakan opsi [A] (Tambah Akun) untuk menambahkan dompet lain secara manual (dengan Private Key atau Seed Phrase).
Gunakan opsi [S] (Ganti Akun) untuk beralih di antara dompet yang dimuat.
Jelajahi menu lainnya untuk melakukan transaksi, memeriksa saldo, dan lainnya!

## 🚨 Catatan Penting & Peringatan Keamanan
INI HANYA UNTUK TESTNET: Klien ini dikembangkan dan dikonfigurasi untuk testnet Octra (https://octra.network). 
JANGAN menggunakannya untuk berinteraksi dengan mainnet Octra
dengan dana sungguhan kecuali Anda memahami sepenuhnya risiko yang ada dan telah melakukan audit keamanan yang ketat.
KEAMANAN KUNCI PRIVAT: Penyimpanan kunci privat di wallet.json dalam teks biasa adalah risiko keamanan yang sangat tinggi. Ini hanya untuk tujuan pengembangan dan pengujian. Untuk penggunaan di dunia nyata dengan dana yang berharga, Anda harus menerapkan enkripsi yang kuat untuk file dompet Anda atau menggunakan solusi manajemen kunci yang aman.
Derivasi Alamat: Skema derivasi alamat yang digunakan dalam skrip (misalnya, Base64(SHA256(public_key_raw_bytes))) adalah asumsi berdasarkan format yang terlihat. Jika alamat dompet Octra Anda tidak cocok, itu berarti Octra menggunakan algoritma derivasi yang berbeda. Anda mungkin perlu menyesuaikan kode derive_octra_keys jika Anda ingin alamat yang diturunkan cocok dengan yang ada di dompet eksternal Anda.

## 🤝 Kontribusi
Jika Anda menemukan bug atau memiliki ide untuk perbaikan, jangan ragu untuk membuka issue atau mengirimkan pull request. Kontribusi selalu diterima!

## 📄 Lisensi
Proyek ini dilisensikan di bawah MIT License.
