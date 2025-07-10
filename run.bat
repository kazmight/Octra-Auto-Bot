@echo off
setlocal

:: Periksa apakah python terinstal
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Python tidak ditemukan. Mohon instal Python.
    exit /b 1
)

:: Buat virtual environment jika belum ada
if not exist "venv" (
    echo Membuat virtual environment...
    python -m venv venv
)

:: Aktifkan virtual environment
echo Mengaktifkan virtual environment...
call venv\Scripts\activate.bat

:: Instal dependensi dari requirements.txt
echo Menginstal dependensi dari requirements.txt...
pip install -r requirements.txt

:: Jalankan skrip Python utama
echo Menjalankan Octra Client...
python kazmight.py

endlocal
