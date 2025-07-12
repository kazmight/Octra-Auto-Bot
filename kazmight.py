#!/usr/bin/env python3 
import json, base64, hashlib, time, sys, re, os, shutil, asyncio, aiohttp, threading
from datetime import datetime, timedelta
import nacl.signing
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import ssl
import signal


from hdwallet import HDWallet
from mnemonic import Mnemonic as Bip39Mnemonic


class OCTRA:
    BIP44_COIN_TYPE = 60


c = {'r': '\033[0m', 'b': '\033[34m', 'c': '\033[36m', 'g': '\033[32m', 'y': '\033[33m', 'R': '\033[31m', 'B': '\033[1m', 'bg': '\033[44m', 'bgr': '\033[41m', 'bgg': '\033[42m', 'w': '\033[37m'}

loaded_accounts = [] 
current_account_idx = -1 
rpc = 'https://octra.network' 

sk, pub = None, None
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000
h = []
cb, cn, lu, lh = None, None, 0, 0
session = None
stop_flag = threading.Event()
spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
spinner_idx = 0

def cls():
    """Menghapus layar konsol."""
    os.system('cls' if os.name == 'nt' else 'clear')

def sz():
    """Mengembalikan ukuran terminal."""
    return shutil.get_terminal_size((80, 25))

def fill():
    """Mengisi seluruh layar terminal dengan spasi latar belakang."""
    cr = sz()
    print(f"{c['bg']}", end='')
    for _ in range(cr[1]):
        print(" " * cr[0])
    print("\033[H", end='') 

def box(x, y, w, h, t=""):
    """Menggambar kotak di terminal pada posisi x,y dengan lebar w dan tinggi h, opsional dengan judul."""
    
    print(f"\033[{y};{x}H{c['bg']}{c['w']}┌{'─' * (w - 2)}┐{c['bg']}")
    if t:
        
        display_t = f" {c['B']}{t} {c['w']}"
        if len(display_t) > (w - 2):
            display_t = display_t[:w-2]
        
        
        print(f"\033[{y};{x}H{c['bg']}{c['w']}┤{display_t.ljust(w - 2)}{c['w']}├{c['bg']}")
        
    
    for i in range(1, h - 1):
        print(f"\033[{y + i};{x}H{c['bg']}{c['w']}│{' ' * (w - 2)}│{c['bg']}")
    
    
    print(f"\033[{y + h - 1};{x}H{c['bg']}{c['w']}└{'─' * (w - 2)}┘{c['bg']}")

def at(x, y, t, cl=''):
    """Mencetak teks pada posisi x,y di konsol dengan warna opsional."""
    print(f"\033[{y};{x}H{c['bg']}{cl}{t}{c['bg']}", end='')

def inp_sync(x, y):
    """Mengambil input sinkron dari pengguna pada posisi x,y."""
    print(f"\033[{y};{x}H", end='', flush=True)
    return input()

def wait_sync():
    """Menunggu pengguna menekan enter untuk melanjutkan."""
    cr = sz()
    msg = "tekan enter untuk melanjutkan..."
    msg_len = len(msg)
    y_pos = cr[1] - 2
    x_pos = max(2, (cr[0] - msg_len) // 2)
    at(x_pos, y_pos, msg, c['y'])
    print(f"\033[{y_pos};{x_pos + msg_len}H", end='', flush=True)
    input()

async def spin_animation(x, y, msg):
    """Menampilkan animasi berputar di konsol."""
    global spinner_idx
    try:
        while True:
            at(x, y, f"{c['c']}{spinner_frames[spinner_idx]} {msg}", c['c'])
            spinner_idx = (spinner_idx + 1) % len(spinner_frames)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        at(x, y, " " * (len(msg) + 3), "")



def derive_octra_keys(seed_or_private_key_input, path="m/44'/60'/0'/0/0"):
    """
    Menurunkan kunci privat dan alamat Octra dari seed phrase atau private key Base64.
    Mengembalikan: (nacl.signing.SigningKey object, pub_key_b64 string, octra_address string)
    """
    try:

        if len(seed_or_private_key_input) >= 43 and '=' in seed_or_private_key_input:
            try:
                priv_bytes = base64.b64decode(seed_or_private_key_input)
                if len(priv_bytes) != 32:
                    raise ValueError(f"Panjang byte kunci privat adalah {len(priv_bytes)}, diharapkan 32 untuk seed Ed25519.")
                
                sk = nacl.signing.SigningKey(priv_bytes)
                verify_key = sk.verify_key
                pub_key_b64 = base64.b64encode(verify_key.encode()).decode()
                
                
                address_raw_bytes = hashlib.sha256(verify_key.encode()).digest()
                octra_address = "oct" + base64.b64encode(address_raw_bytes).decode()
                
                return sk, pub_key_b64, octra_address
            except Exception:
                pass 

        
        if Bip39Mnemonic.check(seed_or_private_key_input):
            try:

                hdwallet_ed25519 = HDWallet(symbol="TRON") 
                hdwallet_ed25519.from_mnemonic(mnemonic=seed_or_private_key_input)
                hdwallet_ed25519.from_path(path="m/44'/195'/0'/0/0") 
                
                private_key_hex = hdwallet_ed25519.private_key()
                if not private_key_hex:
                    raise ValueError("HDWallet tidak menghasilkan kunci privat untuk Ed25519.")
                
                private_key_bytes = bytes.fromhex(private_key_hex)
                
                if len(private_key_bytes) != 32:
                    raise ValueError(f"Kunci privat Ed25519 yang diturunkan adalah {len(private_key_bytes)} byte, diharapkan 32.")

                sk = nacl.signing.SigningKey(private_key_bytes)
                verify_key = sk.verify_key
                pub_key_b64 = base64.b64encode(verify_key.encode()).decode()
                
                
                address_raw_bytes = hashlib.sha256(verify_key.encode()).digest()
                octra_address = "oct" + base64.b64encode(address_raw_bytes).decode()
                
                return sk, pub_key_b64, octra_address
            except Exception:
                return None, None, None 
        else:
            return None, None, None 
    except Exception: 
        return None, None, None

async def add_account_ui():
    """UI untuk menambahkan akun dompet baru."""
    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    
    box(x, y, w, hb, "Tambah Akun Baru")
    at(x + 2, y + 2, "Nama Akun (contoh: 'Akun Utama'):", c['y'])
    account_name = inp_sync(x + 2, y + 3)
    if not account_name:
        return

    at(x + 2, y + 5, "Pilih metode:", c['c'])
    at(x + 4, y + 6, "[1] Dari Private Key (Base64)", c['w'])
    at(x + 4, y + 7, "[2] Dari Seed Phrase (12/24 Kata)", c['w'])
    at(x + 4, y + 8, "[0] Batal", c['w'])
    at(x + 2, y + 10, "Pilihan: ", c['B'] + c['y'])
    choice = inp_sync(x + 11, y + 10)
    
    sk_obj, pub_key_b64, octra_addr = None, None, None
    input_value = None

    if choice == '1':
        at(x + 2, y + 12, "Masukkan Private Key (Base64 Encoded):", c['y'])
        input_value = inp_sync(x + 2, y + 13)
        if input_value:
            sk_obj, pub_key_b64, octra_addr = derive_octra_keys(input_value)
    elif choice == '2':
        at(x + 2, y + 12, "Masukkan Seed Phrase (pisahkan dengan spasi):", c['y'])
        input_value = inp_sync(x + 2, y + 13)
        if input_value:
            sk_obj, pub_key_b64, octra_addr = derive_octra_keys(input_value)
    elif choice == '0':
        return

    if sk_obj and octra_addr and pub_key_b64:
        loaded_accounts.append({
            'name': account_name,
            'priv_raw': input_value, 
            'priv': base64.b64encode(sk_obj.encode()).decode(), 
            'addr': octra_addr,
            'pub': pub_key_b64,
            'sk_obj': sk_obj 
        })
        at(x + 2, y + 15, f"✓ Akun '{account_name}' ({octra_addr[:10]}...) berhasil ditambahkan!", c['bgg'] + c['w'])
        global current_account_idx
        if current_account_idx == -1: 
            current_account_idx = 0
            set_active_account(0)
    else:
        at(x + 2, y + 15, "✗ Gagal menambahkan akun. Input tidak valid atau format salah.", c['bgr'] + c['w'])
    wait_sync()

def set_active_account(idx):
    """Menetapkan akun yang ditentukan sebagai akun yang sedang aktif."""
    global current_account_idx, sk, pub, h, cb, cn, lu, lh
    if 0 <= idx < len(loaded_accounts):
        current_account_idx = idx
        active_account = loaded_accounts[idx]
        globals()['priv'] = active_account['priv']
        globals()['addr'] = active_account['addr']
        globals()['sk'] = active_account['sk_obj']
        globals()['pub'] = active_account['pub']
        
        
        cb, cn, lu, lh = None, None, 0, 0
        h.clear()
        
        return True
    return False

async def switch_account_ui():
    """UI untuk beralih antar akun yang dimuat."""
    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    
    box(x, y, w, hb, "Pilih Akun")
    
    if not loaded_accounts:
        at(x + 2, y + 2, "Tidak ada akun yang dimuat.", c['y'])
        wait_sync()
        return

    at(x + 2, y + 2, "Akun yang Tersedia:", c['c'])
    for i, acc in enumerate(loaded_accounts):
        status = " (Aktif)" if i == current_account_idx else ""
        at(x + 4, y + 4 + i, f"[{i+1}] {acc['name']} ({acc['addr'][:10]}...){status}", c['w'] if i != current_account_idx else c['B'] + c['g'])
    
    at(x + 2, y + 4 + len(loaded_accounts) + 1, "Pilih nomor akun (0 untuk batal):", c['y'])
    choice = inp_sync(x + 2, y + 4 + len(loaded_accounts) + 2)
    
    try:
        idx = int(choice) - 1
        if idx == -1:
            return
        if set_active_account(idx):
            at(x + 2, y + 4 + len(loaded_accounts) + 4, f"✓ Akun beralih ke '{loaded_accounts[idx]['name']}'", c['bgg'] + c['w'])
        else:
            at(x + 2, y + 4 + len(loaded_accounts) + 4, "✗ Pilihan tidak valid.", c['bgr'] + c['w'])
    except ValueError:
        at(x + 2, y + 4 + len(loaded_accounts) + 4, "✗ Masukkan nomor yang valid.", c['bgr'] + c['w'])
    wait_sync()


def ld():
    """
    Mencoba memuat akun dari wallet.json.
    Mendukung objek dompet tunggal atau daftar objek dompet.
    """
    global priv, addr, rpc, sk, pub, loaded_accounts, current_account_idx
    
    
    loaded_accounts.clear() 
    current_account_idx = -1

    try:
        wallet_path = os.path.expanduser("~/.octra/wallet.json")
        if not os.path.exists(wallet_path):
            wallet_path = "wallet.json"
        
        with open(wallet_path, 'r') as f:
            data = json.load(f)
        
        
        wallets_to_load = []
        if isinstance(data, list):
            wallets_to_load = data
        elif isinstance(data, dict):
            
            wallets_to_load.append(data)
        else:
            print(f"{c['R']}Error: Format wallet.json tidak dikenal (bukan objek atau daftar).{c['r']}")
            return False

        if not wallets_to_load:
            print(f"{c['y']}Peringatan: wallet.json kosong atau tidak berisi akun. Anda perlu menambah akun secara manual (opsi 'A').{c['r']}")
            return True 

        accounts_loaded_count = 0
        for i, d in enumerate(wallets_to_load):
            priv_b64 = d.get('priv')
            loaded_addr = d.get('addr')
            loaded_rpc_per_account = d.get('rpc', 'https://octra.network') 

            if not priv_b64 or not loaded_addr:
                print(f"{c['y']}Peringatan: Akun ke-{i+1} di wallet.json tidak lengkap (kunci/alamat hilang). Melewati.{c['r']}")
                continue

            try:
                
                sk_obj, derived_pub_b64, derived_octra_addr = derive_octra_keys(priv_b64)

                if not sk_obj: 
                    print(f"{c['R']}Error: Private key di akun ke-{i+1} wallet.json tidak valid atau tidak kompatibel. Melewati.{c['r']}")
                    continue
                
                account_name = d.get('name', f"wallet.json_account_{i+1}") 

                loaded_accounts.append({
                    'name': account_name,
                    'priv_raw': priv_b64, 
                    'priv': priv_b64,
                    'addr': loaded_addr, 
                    'pub': derived_pub_b64, 
                    'sk_obj': sk_obj
                })
                accounts_loaded_count += 1

                
                if derived_octra_addr != loaded_addr:
                    print(f"{c['y']}Peringatan ({account_name}): Alamat dari wallet.json ({loaded_addr}) berbeda dengan yang diturunkan ({derived_octra_addr}).{c['r']}")
                    print(f"{c['y']}Ini bisa berarti skema derivasi alamat Octra berbeda. Periksa saldo di Octra Explorer untuk {loaded_addr}.{c['r']}")
                    time.sleep(1) #
                
                
                if accounts_loaded_count == 1:
                    globals()['rpc'] = loaded_rpc_per_account
                    if not loaded_rpc_per_account.startswith('https://') and 'localhost' not in loaded_rpc_per_account:
                        print(f"{c['R']}⚠️  WARNING: Menggunakan koneksi HTTP yang tidak aman untuk RPC: {loaded_rpc_per_account}{c['r']}")
                        time.sleep(1) 

            except Exception as e:
                print(f"{c['R']}Error saat memproses akun ke-{i+1} dari wallet.json: {e}. Melewati.{c['r']}")
                continue

        if accounts_loaded_count == 0:
            print(f"{c['y']}Peringatan: Tidak ada akun yang berhasil dimuat dari wallet.json. Anda perlu menambah akun secara manual (opsi 'A').{c['r']}")
            return True 

        current_account_idx = 0
        set_active_account(0) 
        print(f"{c['g']}✓ {accounts_loaded_count} akun berhasil dimuat dari wallet.json.{c['r']}")
        time.sleep(2) 
        return True

    except FileNotFoundError:
        print(f"{c['y']}Peringatan: wallet.json tidak ditemukan. Anda perlu menambah akun secara manual (opsi 'A').{c['r']}")
        return True 
    except json.JSONDecodeError:
        print(f"{c['R']}Error: wallet.json tidak valid (format JSON rusak).{c['r']}")
        return False
    except Exception as e:
        print(f"{c['R']}Error umum saat memuat wallet.json: {e}{c['r']}")
        return False



def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def decrypt_client_balance(encrypted_data, privkey_b64):
    if encrypted_data == "0" or not encrypted_data:
        return 0
    
    if not encrypted_data.startswith("v2|"):
        privkey_bytes = base64.b64decode(privkey_b64)
        salt = b"octra_encrypted_balance_v1"
        key = hashlib.sha256(salt + privkey_bytes).digest() + hashlib.sha256(privkey_bytes + salt).digest()
        key = key[:32]
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 32:
                return 0
            
            nonce = data[:16]
            tag = data[16:32]
            encrypted = data[32:]
            
            expected_tag = hashlib.sha256(nonce + encrypted + key).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                return 0
            
            decrypted = bytearray()
            key_hash = hashlib.sha256(key + nonce).digest()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_hash[i % 32])
            
            return int(decrypted.decode())
        except:
            return 0
    
    try:
        b64_data = encrypted_data[3:]
        raw = base64.b64decode(b64_data)
        
        if len(raw) < 28:
            return 0
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        key = derive_encryption_key(privkey_b64)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return 0

def derive_shared_secret_for_claim(my_privkey_b64, ephemeral_pubkey_b64):
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)
    
    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        larger, smaller = my_pubkey_bytes, eph_pub_bytes
    
    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

def decrypt_private_amount(encrypted_data, shared_secret):
    if not encrypted_data or not encrypted_data.startswith("v2|"):
        return None
    
    try:
        raw = base64.b64decode(encrypted_data[3:])
        if len(raw) < 28:
            return None
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return None

async def req(m, p, d=None, t=10):
    global session
    if not session:
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context, force_close=True)
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=t),
            connector=connector,
            json_serialize=json.dumps
        )
    try:
        current_rpc = rpc
        url = f"{current_rpc}{p}"
        
        kwargs = {}
        if m == 'POST' and d:
            kwargs['json'] = d
        
        async with getattr(session, m.lower())(url, **kwargs) as resp:
            text = await resp.text()
            
            try:
                j = json.loads(text) if text.strip() else None
            except:
                j = None
            
            return resp.status, text, j
    except asyncio.TimeoutError:
        return 0, "timeout", None
    except Exception as e:
        return 0, str(e), None

async def req_private(path, method='GET', data=None):
    current_priv = globals().get('priv')
    if not current_priv:
        return False, {"error": "No active account or private key available."}
        
    headers = {"X-Private-Key": current_priv}
    try:
        current_rpc = rpc
        url = f"{current_rpc}{path}"
        
        kwargs = {'headers': headers}
        if method == 'POST' and data:
            kwargs['json'] = data
            
        async with getattr(session, method.lower())(url, **kwargs) as resp:
            text = await resp.text()
            
            if resp.status == 200:
                try:
                    return True, json.loads(text) if text.strip() else {}
                except:
                    return False, {"error": "Invalid JSON response"}
            else:
                return False, {"error": f"HTTP {resp.status}"}
                
    except Exception as e:
        return False, {"error": str(e)}

async def st():
    global cb, cn, lu
    
    if current_account_idx == -1:
        cb, cn, lu = None, None, 0
        return None, None

    current_addr = globals().get('addr')
    if not current_addr:
        cb, cn, lu = None, None, 0
        return None, None
        
    now = time.time()
    if cb is not None and (now - lu) < 30:
        return cn, cb
    
    results = await asyncio.gather(
        req('GET', f'/balance/{current_addr}'),
        req('GET', '/staging', 5),
        return_exceptions=True
    )
    
    s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
    s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
    
    if s == 200 and j:
        cn = int(j.get('nonce', 0))
        cb = float(j.get('balance', 0))
        lu = now
        if s2 == 200 and j2:
            our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == current_addr]
            if our:
                cn = max(cn, max(int(tx.get('nonce', 0)) for tx in our))
    elif s == 404:
        cn, cb, lu = 0, 0.0, now
    elif s == 200 and t and not j:
        try:
            parts = t.strip().split()
            if len(parts) >= 2:
                cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                cn = int(parts[1]) if parts[1].isdigit() else 0
                lu = now
            else:
                cn, cb = None, None
        except:
            cn, cb = None, None
    return cn, cb

async def get_address_info(address):
    s, t, j = await req('GET', f'/address/{address}')
    if s == 200:
        return j
    return None

async def get_public_key(address):
    s, t, j = await req('GET', f'/public_key/{address}')
    if s == 200:
        return j.get("public_key")
    return None

async def get_encrypted_balance():
    current_addr = globals().get('addr')
    if not current_addr:
        return None
    
    ok, result = await req_private(f"/view_encrypted_balance/{current_addr}")
    
    if ok:
        try:
            return {
                "public": float(result.get("public_balance", "0").split()[0]),
                "public_raw": int(result.get("public_balance_raw", "0")),
                "encrypted": float(result.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(result.get("encrypted_balance_raw", "0")),
                "total": float(result.get("total_balance", "0").split()[0])
            }
        except:
            return None
    else:
        return None

async def encrypt_balance(amount):
    current_priv = globals().get('priv')
    current_addr = globals().get('addr')
    if not current_priv or not current_addr:
        return False, {"error": "No active account or private key available."}

    enc_data = await get_encrypted_balance()
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    new_encrypted_raw = current_encrypted_raw + int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, current_priv)
    
    data = {
        "address": current_addr,
        "amount": str(int(amount * μ)),
        "private_key": current_priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/encrypt_balance', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def decrypt_balance(amount):
    current_priv = globals().get('priv')
    current_addr = globals().get('addr')
    if not current_priv or not current_addr:
        return False, {"error": "No active account or private key available."}

    enc_data = await get_encrypted_balance()
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    if current_encrypted_raw < int(amount * μ):
        return False, {"error": "insufficient encrypted balance"}
    
    new_encrypted_raw = current_encrypted_raw - int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, current_priv)
    
    data = {
        "address": current_addr,
        "amount": str(int(amount * μ)),
        "private_key": current_priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/decrypt_balance', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def create_private_transfer(to_addr, amount):
    current_priv = globals().get('priv')
    current_addr = globals().get('addr')
    current_pub = globals().get('pub')
    if not current_priv or not current_addr or not current_pub:
        return False, {"error": "No active account or private key/public key available."}

    addr_info = await get_address_info(to_addr)
    if not addr_info or not addr_info.get("has_public_key"):
        return False, {"error": "Recipient has no public key"}
    
    to_public_key = await get_public_key(to_addr)
    if not to_public_key:
        return False, {"error": "Cannot get recipient public key"}
    
    data = {
        "from": current_addr,
        "to": to_addr,
        "amount": str(int(amount * μ)),
        "from_private_key": current_priv,
        "to_public_key": to_public_key
    }
    
    s, t, j = await req('POST', '/private_transfer', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def get_pending_transfers():
    current_addr = globals().get('addr')
    if not current_addr:
        return []
        
    ok, result = await req_private(f"/pending_private_transfers?address={current_addr}")
    
    if ok:
        transfers = result.get("pending_transfers", [])
        return transfers
    else:
        return []

async def claim_private_transfer(transfer_id):
    current_priv = globals().get('priv')
    current_addr = globals().get('addr')
    if not current_priv or not current_addr:
        return False, {"error": "No active account or private key available."}

    data = {
        "recipient_address": current_addr,
        "private_key": current_priv,
        "transfer_id": transfer_id
    }
    
    s, t, j = await req('POST', '/claim_private_transfer', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def gh():
    global h, lh
    
    current_addr = globals().get('addr')
    if not current_addr:
        h.clear()
        lh = 0
        return

    now = time.time()
    if now - lh < 60 and h:
        return
    s, t, j = await req('GET', f'/address/{current_addr}?limit=20')
    if s != 200 or (not j and not t):
        return
    
    if j and 'recent_transactions' in j:
        tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
        tx_results = await asyncio.gather(*[req('GET', f'/tx/{hash}', 5) for hash in tx_hashes], return_exceptions=True)
        
        existing_hashes = {tx['hash'] for tx in h}
        nh = []
        
        for i, (ref, result) in enumerate(zip(j.get('recent_transactions', []), tx_results)):
            if isinstance(result, Exception):
                continue
            s2, _, j2 = result
            if s2 == 200 and j2 and 'parsed_tx' in j2:
                p = j2['parsed_tx']
                tx_hash = ref['hash']
                
                if tx_hash in existing_hashes:
                    continue
                
                ii = p.get('to') == current_addr
                ar = p.get('amount_raw', p.get('amount', '0'))
                a = float(ar) if '.' in str(ar) else int(ar) / μ
                msg = None
                if 'data' in j2:
                    try:
                        data = json.loads(j2['data'])
                        msg = data.get('message')
                    except:
                        pass
                nh.append({
                    'time': datetime.fromtimestamp(p.get('timestamp', 0)),
                    'hash': tx_hash,
                    'amt': a,
                    'to': p.get('to') if not ii else p.get('from'),
                    'type': 'in' if ii else 'out',
                    'ok': True,
                    'nonce': p.get('nonce', 0),
                    'epoch': ref.get('epoch', 0),
                    'msg': msg
                })
        
        oh = datetime.now() - timedelta(hours=1)
        h[:] = sorted(nh + [tx for tx in h if tx.get('time', datetime.now()) > oh], key=lambda x: x['time'], reverse=True)[:50]
        lh = now
    elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
        h.clear()
        lh = now

def mk(to, a, n, msg=None):
    current_sk = globals().get('sk')
    current_pub = globals().get('pub')
    current_addr = globals().get('addr')
    
    if not current_sk or not current_pub or not current_addr:
        raise ValueError("No active account or keys available for transaction creation.")

    tx = {
        "from": current_addr,
        "to_": to,
        "amount": str(int(a * μ)),
        "nonce": int(n),
        "ou": "1" if a < 1000 else "3",
        "timestamp": time.time()
    }
    if msg:
        tx["message"] = msg
    bl = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    sig = base64.b64encode(current_sk.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=current_pub)
    return tx, hashlib.sha256(bl.encode()).hexdigest()

async def snd(tx):
    t0 = time.time()
    s, t, j = await req('POST', '/send-tx', tx)
    dt = time.time() - t0
    if s == 200:
        if j and j.get('status') == 'accepted':
            return True, j.get('tx_hash', ''), dt, j
        elif t.lower().startswith('ok'):
            return True, t.split()[-1], dt, None
    return False, json.dumps(j) if j else t, dt, j

async def expl(x, y, w, hb):
    box(x, y, w, hb, "Wallet Explorer")
    
    if current_account_idx != -1:
        active_acc = loaded_accounts[current_account_idx]
        current_addr = active_acc['addr']
        current_pub = active_acc['pub']
        at(x + 2, y + 2, "Akun Aktif:", c['c'])
        at(x + 15, y + 2, active_acc['name'], c['B'] + c['w'])
    else:
        current_addr = "N/A"
        current_pub = "N/A"
        at(x + 2, y + 2, "Akun Aktif:", c['R'])
        at(x + 15, y + 2, "Tidak Ada", c['B'] + c['R'])
    
    at(x + 2, y + 3, "Alamat:", c['c'])
    at(x + 11, y + 3, current_addr, c['w'])
    
    n, b = await st()
    at(x + 2, y + 4, "Saldo:", c['c'])
    at(x + 11, y + 4, f"{b:.6f} OCT" if b is not None else "---", c['B'] + c['g'] if b else c['w'])
    at(x + 2, y + 5, "Nonce:", c['c'])
    at(x + 11, y + 5, str(n) if n is not None else "---", c['w'])
    at(x + 2, y + 6, "Public:", c['c'])
    at(x + 11, y + 6, current_pub[:40] + "..." if current_pub != "N/A" else "N/A", c['w'])
    
    if current_account_idx != -1:
        try:
            enc_data = await get_encrypted_balance()
            if enc_data:
                at(x + 2, y + 7, "Terenkripsi:", c['c'])
                at(x + 15, y + 7, f"{enc_data['encrypted']:.6f} OCT", c['B'] + c['y'])
                
                pending = await get_pending_transfers()
                if pending:
                    at(x + 2, y + 8, "Dapat Diklaim:", c['c'])
                    at(x + 15, y + 8, f"{len(pending)} transfer", c['B'] + c['g'])
        except Exception:
            pass
    else:
        at(x + 2, y + 7, "Terenkripsi:", c['R'])
        at(x + 15, y + 7, "N/A (Pilih akun)", c['B'] + c['R'])
        at(x + 2, y + 8, "Dapat Diklaim:", c['R'])
        at(x + 15, y + 8, "N/A (Pilih akun)", c['B'] + c['R'])

    _, _, j = await req('GET', '/staging', 2)
    sc = len([tx for tx in j.get('staged_transactions', []) if tx.get('from') == current_addr]) if j else 0
    at(x + 2, y + 9, "Staging:", c['c'])
    at(x + 11, y + 9, f"{sc} tertunda" if sc else "tidak ada", c['y'] if sc else c['w'])
    at(x + 1, y + 10, "─" * (w - 2), c['w'])
    
    at(x + 2, y + 11, "Transaksi Terbaru:", c['B'] + c['c'])
    if not h:
        at(x + 2, y + 13, "Belum ada transaksi", c['y'])
    else:
        at(x + 2, y + 13, "Waktu     Tipe  Jumlah      Alamat", c['c'])
        at(x + 2, y + 14, "─" * (w - 4), c['w'])
        seen_hashes = set()
        display_count = 0
        sorted_h = sorted(h, key=lambda x: x['time'], reverse=True)
        for tx in sorted_h:
            if tx['hash'] in seen_hashes:
                continue
            seen_hashes.add(tx['hash'])
            if display_count >= min(len(h), hb - 18):
                break
            is_pending = not tx.get('epoch')
            time_color = c['y'] if is_pending else c['w']
            at(x + 2, y + 15 + display_count, tx['time'].strftime('%H:%M:%S'), time_color)
            at(x + 11, y + 15 + display_count, "masuk" if tx['type'] == 'in' else "keluar", c['g'] if tx['type'] == 'in' else c['R'])
            at(x + 18, y + 15 + display_count, f"{float(tx['amt']):>10.6f}", c['w'])
            at(x + 30, y + 15 + display_count, str(tx.get('to', '---')), c['y'])
            if tx.get('msg'):
                at(x + 77, y + 15 + display_count, "msg", c['c'])
            status_text = "pen" if is_pending else f"e{tx.get('epoch', 0)}"
            status_color = c['y'] + c['B'] if is_pending else c['c']
            at(x + w - 6, y + 15 + display_count, status_text, status_color)
            display_count += 1

def menu(x, y, w, h):
    box(x, y, w, h, "Perintah")
    at(x + 2, y + 2, "[1] Kirim Transaksi", c['w'])
    at(x + 2, y + 3, "[2] Refresh", c['w'])
    at(x + 2, y + 4, "[3] Multi Kirim", c['w'])
    at(x + 2, y + 5, "[4] Enkripsi Saldo", c['w'])
    at(x + 2, y + 6, "[5] Dekripsi Saldo", c['w'])
    at(x + 2, y + 7, "[6] Transfer Privat", c['w'])
    at(x + 2, y + 8, "[7] Klaim Transfer", c['w'])
    at(x + 2, y + 9, "[8] Ekspor Kunci", c['w'])
    at(x + 2, y + 10, "[9] Bersihkan Riwayat", c['w'])
    at(x + 2, y + 11, "[A] Tambah Akun", c['B'] + c['y'])
    at(x + 2, y + 12, "[S] Ganti Akun", c['B'] + c['y'])
    at(x + 2, y + 13, "[0] Keluar", c['w'])
    at(x + 2, y + h - 2, "Perintah: ", c['B'] + c['y'])

async def scr():
    cr = sz()
    cls()
    fill()
    t = f" Octra Pre client Testnet multi-account By Kazmight │ {datetime.now().strftime('%H:%M:%S')} "
    at((cr[0] - len(t)) // 2, 1, t, c['B'] + c['w'])
    
    sidebar_w = 28
    menu(2, 3, sidebar_w, 17)
    
    info_y = 21
    box(2, info_y, sidebar_w, 9)
    at(4, info_y + 2, "Lingkungan testnet.", c['y'])
    at(4, info_y + 3, "Diperbarui secara aktif.", c['y'])
    at(4, info_y + 4, "Pantau perubahan!", c['y'])
    at(4, info_y + 5, "Transaksi privat", c['g'])
    at(4, info_y + 6, "diaktifkan", c['g'])
    at(4, info_y + 7, "Token: tanpa nilai", c['R'])
    
    explorer_x = sidebar_w + 4
    explorer_w = cr[0] - explorer_x - 2
    await expl(explorer_x, 3, explorer_w, cr[1] - 6)
    
    at(2, cr[1] - 1, " " * (cr[0] - 4), c['bg'])
    
    if current_account_idx == -1:
        at(2, cr[1] - 1, "Mohon tambahkan/pilih akun (A/S)", c['bgr'] + c['w'])
    else:
        at(2, cr[1] - 1, f"Akun aktif: {loaded_accounts[current_account_idx]['name']} ({loaded_accounts[current_account_idx]['addr'][:10]}...) | Siap", c['bgg'] + c['w'])
        
    return inp_sync(12, 18)

async def tx():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 85, 26
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "Kirim Transaksi")
    at(x + 2, y + 2, "Alamat Tujuan: (atau [esc] untuk batal)", c['y'])
    at(x + 2, y + 3, "─" * (w - 4), c['w'])
    to = inp_sync(x + 2, y + 4)
    if not to or to.lower() == 'esc':
        return
    if not b58.match(to):
        at(x + 2, y + 14, "Alamat tidak valid!", c['bgr'] + c['w'])
        at(x + 2, y + 15, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    at(x + 2, y + 5, f"Kepada: {to}", c['g'])
    at(x + 2, y + 7, "Jumlah: (atau [esc] untuk batal)", c['y'])
    at(x + 2, y + 8, "─" * (w - 4), c['w'])
    a = inp_sync(x + 2, y + 9)
    if not a or a.lower() == 'esc':
        return
    if not re.match(r"^\d+(\.\d+)?$", a) or float(a) <= 0:
        at(x + 2, y + 14, "Jumlah tidak valid!", c['bgr'] + c['w'])
        at(x + 2, y + 15, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    a = float(a)
    at(x + 2, y + 10, f"Jumlah: {a:.6f} OCT", c['g'])
    at(x + 2, y + 12, "Pesan (opsional, maks 1024): (atau Enter untuk melewati)", c['y'])
    at(x + 2, y + 13, "─" * (w - 4), c['w'])
    msg = inp_sync(x + 2, y + 14)
    if not msg:
        msg = None
    elif len(msg) > 1024:
        msg = msg[:1024]
        at(x + 2, y + 15, "Pesan dipotong menjadi 1024 karakter", c['y'])
    
    global lu
    lu = 0
    n, b = await st()
    if n is None:
        at(x + 2, y + 17, "Gagal mendapatkan nonce!", c['bgr'] + c['w'])
        at(x + 2, y + 18, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    if b is None or b < a:
        at(x + 2, y + 17, f"Saldo tidak mencukupi ({b:.6f} < {a})", c['bgr'] + c['w'])
        at(x + 2, y + 18, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    at(x + 2, y + 16, "─" * (w - 4), c['w'])
    at(x + 2, y + 17, f"Kirim {a:.6f} OCT", c['B'] + c['g'])
    at(x + 2, y + 18, f"Kepada:  {to}", c['g'])
    if msg:
        at(x + 2, y + 19, f"Pesan: {msg[:50]}{'...' if len(msg) > 50 else ''}", c['c'])
    at(x + 2, y + 20, f"Biaya: {'0.001' if a < 1000 else '0.003'} OCT (nonce: {n + 1})", c['y'])
    at(x + 2, y + 21, "[y]a / [n]o: ", c['B'] + c['y'])
    if (inp_sync(x + 16, y + 21)).strip().lower() != 'y':
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 22, "Mengirim transaksi"))
    
    try:
        t, _ = mk(to, a, n + 1, msg)
        ok, hs, dt, r = await snd(t)
    except ValueError as e:
        ok = False
        hs = str(e)
        dt = 0
        r = None
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if ok:
        for i in range(17, 25):
            at(x + 2, y + i, " " * (w - 4), c['bg'])
        at(x + 2, y + 20, f"✓ Transaksi diterima!", c['bgg'] + c['w'])
        at(x + 2, y + 21, f"Hash: {hs[:64]}...", c['g'])
        at(x + 2, y + 22, f"      {hs[64:]}", c['g'])
        at(x + 2, y + 23, f"Waktu: {dt:.2f}s", c['w'])
        if r and 'pool_info' in r:
            at(x + 2, y + 24, f"Pool: {r['pool_info'].get('total_pool_size', 0)} transaksi tertunda", c['y'])
        h.append({
            'time': datetime.now(),
            'hash': hs,
            'amt': a,
            'to': to,
            'type': 'out',
            'ok': True,
            'msg': msg
        })
        lu = 0
    else:
        at(x + 2, y + 20, f"✗ Transaksi gagal!", c['bgr'] + c['w'])
        at(x + 2, y + 21, f"Error: {str(hs)[:w - 10]}", c['R'])
    wait_sync()

async def multi():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 70, cr[1] - 4
    x = (cr[0] - w) // 2
    y = 2
    box(x, y, w, hb, "Kirim Multi")
    at(x + 2, y + 2, "Masukkan penerima (alamat jumlah), baris kosong untuk selesai:", c['y'])
    at(x + 2, y + 3, "Ketik [esc] untuk batal", c['c'])
    at(x + 2, y + 4, "─" * (w - 4), c['w'])
    rcp = []
    tot = 0
    ly = y + 5
    while ly < y + hb - 8:
        at(x + 2, ly, f"[{len(rcp) + 1}] ", c['c'])
        l = inp_sync(x + 7, ly)
        if l.lower() == 'esc':
            return
        if not l:
            break
        p = l.split()
        if len(p) == 2 and b58.match(p[0]) and re.match(r"^\d+(\.\d+)?$", p[1]) and float(p[1]) > 0:
            a = float(p[1])
            rcp.append((p[0], a))
            tot += a
            at(x + 50, ly, f"+{a:.6f}", c['g'])
            ly += 1
        else:
            at(x + 50, ly, "tidak valid!", c['R'])
    if not rcp:
        return
    at(x + 2, y + hb - 7, "─" * (w - 4), c['w'])
    at(x + 2, y + hb - 6, f"Total: {tot:.6f} OCT ke {len(rcp)} alamat", c['B'] + c['y'])
    global lu
    lu = 0
    n, b = await st()
    if n is None:
        at(x + 2, y + hb - 5, "Gagal mendapatkan nonce!", c['bgr'] + c['w'])
        at(x + 2, y + hb - 4, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    if not b or b < tot:
        at(x + 2, y + hb - 5, f"Saldo tidak mencukupi! ({b:.6f} < {tot})", c['bgr'] + c['w'])
        at(x + 2, y + hb - 4, "Tekan Enter untuk kembali...", c['y'])
        wait_sync()
        return
    at(x + 2, y + hb - 5, f"Kirim semua? [y/n] (nonce awal: {n + 1}): ", c['y'])
    if (inp_sync(x + 48, y + hb - 5)).strip().lower() != 'y':
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + hb - 3, "Mengirim transaksi"))
    
    batch_size = 5
    batches = [rcp[i:i+batch_size] for i in range(0, len(rcp), batch_size)]
    s_total, f_total = 0, 0
    
    for batch_idx, batch in enumerate(batches):
        tasks = []
        for i, (to, a) in enumerate(batch):
            idx = batch_idx * batch_size + i
            at(x + 2, y + hb - 2, f"[{idx + 1}/{len(rcp)}] menyiapkan batch...", c['c'])
            try:
                t, _ = mk(to, a, n + 1 + idx)
                tasks.append(snd(t))
            except ValueError as e:
                f_total += 1
                at(x + 55, y + hb - 2, "✗ gagal (kunci)", c['R'])
                await asyncio.sleep(0.05)
                
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, (result, (to, a)) in enumerate(zip(results, batch)):
            idx = batch_idx * batch_size + i
            if isinstance(result, Exception):
                f_total += 1
                at(x + 55, y + hb - 2, "✗ gagal ", c['R'])
            else:
                ok, hs, _, _ = result
                if ok:
                    s_total += 1
                    at(x + 55, y + hb - 2, "✓ OK   ", c['g'])
                    h.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': a,
                        'to': to,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    f_total += 1
                    at(x + 55, y + hb - 2, "✗ gagal ", c['R'])
            at(x + 2, y + hb - 2, f"[{idx + 1}/{len(rcp)}] {a:.6f} ke {to[:20]}...", c['c'])
            await asyncio.sleep(0.05)
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    lu = 0
    at(x + 2, y + hb - 2, " " * 65, c['bg'])
    at(x + 2, y + hb - 2, f"Selesai: {s_total} sukses, {f_total} gagal", c['bgg'] + c['w'] if f_total == 0 else c['bgr'] + c['w'])
    wait_sync()

async def encrypt_balance_ui():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    
    box(x, y, w, hb, "Enkripsi Saldo")
    
    _, pub_bal = await st()
    enc_data = await get_encrypted_balance()
    
    if not enc_data:
        at(x + 2, y + 10, "Tidak bisa mendapatkan info saldo terenkripsi", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 2, "Saldo Publik:", c['c'])
    at(x + 20, y + 2, f"{pub_bal:.6f} OCT", c['w'])
    
    at(x + 2, y + 3, "Terenkripsi:", c['c'])
    at(x + 20, y + 3, f"{enc_data['encrypted']:.6f} OCT", c['y'])
    
    at(x + 2, y + 4, "Total:", c['c'])
    at(x + 20, y + 4, f"{enc_data['total']:.6f} OCT", c['g'])
    
    at(x + 2, y + 6, "─" * (w - 4), c['w'])
    
    max_encrypt = enc_data['public_raw'] / μ - 1.0
    if max_encrypt <= 0:
        at(x + 2, y + 8, "Saldo publik tidak mencukupi (butuh > 1 OCT untuk biaya)", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 7, f"Maksimal yang bisa dienkripsi: {max_encrypt:.6f} OCT", c['y'])
    
    at(x + 2, y + 9, "Jumlah yang akan dienkripsi:", c['y'])
    amount = inp_sync(x + 21, y + 9)
    
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return
    
    amount = float(amount)
    if amount > max_encrypt:
        at(x + 2, y + 11, f"Jumlah terlalu besar (maks: {max_encrypt:.6f})", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 11, f"Enkripsi {amount:.6f} OCT? [y/n]:", c['B'] + c['y'])
    if (inp_sync(x + 30, y + 11)).strip().lower() != 'y':
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 14, "Menenkripsi saldo"))
    
    ok, result = await encrypt_balance(amount)
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if ok:
        at(x + 2, y + 14, "✓ Enkripsi berhasil diajukan!", c['bgg'] + c['w'])
        at(x + 2, y + 15, f"Hash transaksi: {result.get('tx_hash', 'unknown')[:50]}...", c['g'])
        at(x + 2, y + 16, f"Akan diproses di epoch berikutnya", c['g'])
    else:
        at(x + 2, y + 14, f"✗ Error: {result.get('error', 'unknown')}", c['bgr'] + c['w'])
    
    wait_sync()

async def decrypt_balance_ui():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    
    box(x, y, w, hb, "Dekripsi Saldo")
    
    _, pub_bal = await st()
    enc_data = await get_encrypted_balance()
    
    if not enc_data:
        at(x + 2, y + 10, "Tidak bisa mendapatkan info saldo terenkripsi", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 2, "Saldo Publik:", c['c'])
    at(x + 20, y + 2, f"{pub_bal:.6f} OCT", c['w'])
    
    at(x + 2, y + 3, "Terenkripsi:", c['c'])
    at(x + 20, y + 3, f"{enc_data['encrypted']:.6f} OCT", c['y'])
    
    at(x + 2, y + 4, "Total:", c['c'])
    at(x + 20, y + 4, f"{enc_data['total']:.6f} OCT", c['g'])
    
    at(x + 2, y + 6, "─" * (w - 4), c['w'])
    
    if enc_data['encrypted_raw'] == 0:
        at(x + 2, y + 8, "Tidak ada saldo terenkripsi untuk didekripsi", c['R'])
        wait_sync()
        return
    
    max_decrypt = enc_data['encrypted_raw'] / μ
    at(x + 2, y + 7, f"Maksimal yang bisa didekripsi: {max_decrypt:.6f} OCT", c['y'])
    
    at(x + 2, y + 9, "Jumlah yang akan didekripsi:", c['y'])
    amount = inp_sync(x + 21, y + 9)
    
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return
    
    amount = float(amount)
    if amount > max_decrypt:
        at(x + 2, y + 11, f"Jumlah terlalu besar (maks: {max_decrypt:.6f})", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 11, f"Dekripsi {amount:.6f} OCT? [y/n]:", c['B'] + c['y'])
    if (inp_sync(x + 30, y + 11)).strip().lower() != 'y':
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 14, "Mendekripsi saldo"))
    
    ok, result = await decrypt_balance(amount)
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if ok:
        at(x + 2, y + 14, "✓ Dekripsi berhasil diajukan!", c['bgg'] + c['w'])
        at(x + 2, y + 15, f"Hash transaksi: {result.get('tx_hash', 'unknown')[:50]}...", c['g'])
        at(x + 2, y + 16, f"Akan diproses di epoch berikutnya", c['g'])
    else:
        at(x + 2, y + 14, f"✗ Error: {result.get('error', 'unknown')}", c['bgr'] + c['w'])
    
    wait_sync()

async def private_transfer_ui():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 80, 25
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    
    box(x, y, w, hb, "Transfer Privat")
    
    enc_data = await get_encrypted_balance()
    if not enc_data or enc_data['encrypted_raw'] == 0:
        at(x + 2, y + 10, "Tidak ada saldo terenkripsi yang tersedia", c['R'])
        at(x + 2, y + 11, "Enkripsi beberapa saldo terlebih dahulu", c['y'])
        wait_sync()
        return
    
    at(x + 2, y + 2, f"Saldo terenkripsi: {enc_data['encrypted']:.6f} OCT", c['g'])
    at(x + 2, y + 3, "─" * (w - 4), c['w'])
    
    at(x + 2, y + 5, "Alamat penerima:", c['y'])
    to_addr = inp_sync(x + 2, y + 6)
    
    if not to_addr or not b58.match(to_addr):
        at(x + 2, y + 12, "Alamat tidak valid", c['R'])
        wait_sync()
        return
    
    if to_addr == globals().get('addr'):
        at(x + 2, y + 12, "Tidak bisa mengirim ke diri sendiri", c['R'])
        wait_sync()
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 8, "Memeriksa penerima"))
    
    addr_info = await get_address_info(to_addr)
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if not addr_info:
        at(x + 2, y + 12, "Alamat penerima tidak ditemukan di blockchain", c['R'])
        wait_sync()
        return
    
    if not addr_info.get('has_public_key'):
        at(x + 2, y + 12, "Penerima tidak memiliki kunci publik", c['R'])
        at(x + 2, y + 13, "Mereka perlu membuat transaksi terlebih dahulu", c['y'])
        wait_sync()
        return
    
    at(x + 2, y + 8, f"Saldo penerima: {addr_info.get('balance', 'unknown')}", c['c'])
    
    at(x + 2, y + 10, "Jumlah:", c['y'])
    amount = inp_sync(x + 10, y + 10)
    
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return
    
    amount = float(amount)
    if amount > enc_data['encrypted'] :
        at(x + 2, y + 14, f"Saldo terenkripsi tidak mencukupi", c['R'])
        wait_sync()
        return
    
    at(x + 2, y + 12, "─" * (w - 4), c['w'])
    at(x + 2, y + 13, f"Kirim {amount:.6f} OCT secara privat ke", c['B'])
    at(x + 2, y + 14, to_addr, c['y'])
    at(x + 2, y + 16, "[y]a / [n]o:", c['B'] + c['y'])
    
    if (inp_sync(x + 15, y + 16)).strip().lower() != 'y':
        return
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 18, "Membuat transfer privat"))
    
    ok, result = await create_private_transfer(to_addr, amount)
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if ok:
        at(x + 2, y + 18, "✓ Transfer privat berhasil diajukan!", c['bgg'] + c['w'])
        at(x + 2, y + 19, f"Hash transaksi: {result.get('tx_hash', 'unknown')[:50]}...", c['g'])
        at(x + 2, y + 20, f"Penerima dapat mengklaim di epoch berikutnya", c['g'])
        at(x + 2, y + 21, f"Kunci sementara: {result.get('ephemeral_key', 'unknown')[:40]}...", c['c'])
    else:
        at(x + 2, y + 18, f"✗ Error: {result.get('error', 'unknown')[:w-10]}", c['bgr'] + c['w'])
    
    wait_sync()

async def claim_transfers_ui():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 85, cr[1] - 4
    x = (cr[0] - w) // 2
    y = 2
    
    box(x, y, w, hb, "Klaim Transfer Privat")
    
    spin_task = asyncio.create_task(spin_animation(x + 2, y + 2, "Memuat transfer tertunda"))
    
    transfers = await get_pending_transfers()
    
    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass
    
    if not transfers:
        at(x + 2, y + 10, "Tidak ada transfer tertunda", c['y'])
        wait_sync()
        return
    
    at(x + 2, y + 2, f"Ditemukan {len(transfers)} transfer yang dapat diklaim:", c['B'] + c['g'])
    at(x + 2, y + 4, "#   DARI                JUMLAH         EPOCH   ID", c['c'])
    at(x + 2, y + 5, "─" * (w - 4), c['w'])
    
    display_y = y + 6
    max_display = min(len(transfers), hb - 12)
    
    for i, t in enumerate(transfers[:max_display]):
        amount_str = "[terenkripsi]"
        amount_color = c['y']
        
        if t.get('encrypted_data') and t.get('ephemeral_key'):
            try:
                current_priv = globals().get('priv') 
                if current_priv:
                    shared = derive_shared_secret_for_claim(current_priv, t['ephemeral_key'])
                    amt = decrypt_private_amount(t['encrypted_data'], shared)
                    if amt:
                        amount_str = f"{amt/μ:.6f} OCT"
                        amount_color = c['g']
            except:
                pass
        
        at(x + 2, display_y + i, f"[{i+1}]", c['c'])
        at(x + 8, display_y + i, t['sender'][:20] + "...", c['w'])
        at(x + 32, display_y + i, amount_str, amount_color)
        at(x + 48, display_y + i, f"ep{t.get('epoch_id', '?')}", c['c'])
        at(x + 58, display_y + i, f"#{t.get('id', '?')}", c['y'])
    
    if len(transfers) > max_display:
        at(x + 2, display_y + max_display + 1, f"... dan {len(transfers) - max_display} lainnya", c['y'])
    
    at(x + 2, y + hb - 6, "─" * (w - 4), c['w'])
    at(x + 2, y + hb - 5, "Masukkan nomor untuk mengklaim (0 untuk batal):", c['y'])
    choice = inp_sync(x + 40, y + hb - 5)
    
    if not choice or choice == '0':
        return
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(transfers):
            transfer = transfers[idx]
            transfer_id = transfer['id']
            
            spin_task = asyncio.create_task(spin_animation(x + 2, y + hb - 3, f"Mengklaim transfer #{transfer_id}"))
            
            ok, result = await claim_private_transfer(transfer_id)
            
            spin_task.cancel()
            try:
                await spin_task
            except asyncio.CancelledError:
                pass
            
            if ok:
                at(x + 2, y + hb - 3, f"✓ Diklaim {result.get('amount', 'unknown')}!", c['bgg'] + c['w'])
                at(x + 2, y + hb - 2, "Saldo terenkripsi Anda telah diperbarui", c['g'])
            else:
                error_msg = result.get('error', 'unknown error')
                at(x + 2, y + hb - 3, f"✗ Error: {error_msg[:w-10]}", c['bgr'] + c['w'])
        else:
            at(x + 2, y + hb - 3, "Pilihan tidak valid", c['R'])
    except ValueError:
        at(x + 2, y + hb - 3, "Nomor tidak valid", c['R'])
    except Exception:
        at(x + 2, y + hb - 3, f"Terjadi kesalahan", c['R'])
    
    wait_sync()

async def exp():
    if current_account_idx == -1:
        cls()
        at(2,2, "Tidak ada akun aktif. Mohon tambahkan atau pilih akun terlebih dahulu.", c['R'])
        wait_sync()
        return

    cr = sz()
    cls()
    fill()
    w, hb = 70, 15
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "Ekspor Kunci")
    
    active_acc = loaded_accounts[current_account_idx]
    current_priv = active_acc['priv']
    current_addr = active_acc['addr']
    current_pub = active_acc['pub']

    at(x + 2, y + 2, "Info Dompet Akun Aktif:", c['c'])
    at(x + 2, y + 4, "Alamat:", c['c'])
    at(x + 11, y + 4, current_addr[:32] + "...", c['w'])
    at(x + 2, y + 5, "Saldo:", c['c'])
    n, b = await st()
    at(x + 11, y + 5, f"{b:.6f} OCT" if b is not None else "---", c['g'])
    
    at(x + 2, y + 7, "Opsi Ekspor:", c['y'])
    at(x + 2, y + 8, "[1] Tampilkan Private Key", c['w'])
    at(x + 2, y + 9, "[2] Simpan Dompet Lengkap ke File", c['w'])
    at(x + 2, y + 10, "[3] Salin Alamat ke Clipboard", c['w'])
    at(x + 2, y + 11, "[0] Batal", c['w'])
    at(x + 2, y + 13, "Pilihan: ", c['B'] + c['y'])
    
    choice = inp_sync(x + 10, y + 13)
    choice = choice.strip()
    
    if choice == '1':
        at(x + 2, y + 7, " " * (w - 4), c['bg'])
        at(x + 2, y + 8, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, " " * (w - 4), c['bg'])
        at(x + 2, y + 10, " " * (w - 4), c['bg'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        at(x + 2, y + 13, " " * (w - 4), c['bg'])
        
        at(x + 2, y + 7, "Private Key (JAGA RAHASIA!):", c['R'])
        at(x + 2, y + 8, current_priv[:32], c['R'])
        at(x + 2, y + 9, current_priv[32:], c['R'])
        at(x + 2, y + 11, "Public Key:", c['g'])
        at(x + 2, y + 12, current_pub[:44] + "...", c['g'])
        wait_sync()
        
    elif choice == '2':
        fn = f"octra_wallet_{active_acc['name'].replace(' ', '_')}_{int(time.time())}.json"
        wallet_data = {
            'priv': current_priv,
            'addr': current_addr,
            'pub': current_pub,
            'rpc': rpc
        }
        os.umask(0o077)
        with open(fn, 'w') as f:
            json.dump(wallet_data, f, indent=2)
        os.chmod(fn, 0o600)
        at(x + 2, y + 7, " " * (w - 4), c['bg'])
        at(x + 2, y + 8, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, " " * (w - 4), c['bg'])
        at(x + 2, y + 10, " " * (w - 4), c['bg'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        at(x + 2, y + 13, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, f"Disimpan ke {fn}", c['g'])
        at(x + 2, y + 11, "File mengandung private key - Jaga Keamanan!", c['R'])
        wait_sync()
        
    elif choice == '3':
        try:
            import pyperclip
            pyperclip.copy(current_addr)
            at(x + 2, y + 7, " " * (w - 4), c['bg'])
            at(x + 2, y + 9, "Alamat disalin ke clipboard!", c['g'])
        except:
            at(x + 2, y + 7, " " * (w - 4), c['bg'])
            at(x + 2, y + 9, "Clipboard tidak tersedia", c['R'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        wait_sync()

def signal_handler(sig, frame):
    stop_flag.set()
    if session:
        asyncio.create_task(session.close())
    sys.exit(0)

async def main():
    global session
    
    print("\n--- KAZMIGHT CLIENT OCTRA DIMULAI ---")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if not ld():
        sys.exit("[!] Terjadi kesalahan inisialisasi klien.")
    
    try:
        while not stop_flag.is_set():
            cmd = await scr()
            
            if cmd == '1':
                await tx()
            elif cmd == '2':
                global lu, lh
                lu = lh = 0
                await st()
                await gh()
            elif cmd == '3':
                await multi()
            elif cmd == '4':
                await encrypt_balance_ui()
            elif cmd == '5':
                await decrypt_balance_ui()
            elif cmd == '6':
                await private_transfer_ui()
            elif cmd == '7':
                await claim_transfers_ui()
            elif cmd == '8':
                await exp()
            elif cmd == '9':
                h.clear()
                lh = 0
            elif cmd.lower() == 'a': 
                await add_account_ui()
            elif cmd.lower() == 's': 
                await switch_account_ui()
            elif cmd in ['0', 'q', '']:
                break
    except Exception as e:
        cls()
        print(f"\n{c['R']}Terjadi kesalahan fatal: {e}{c['r']}")
        import traceback
        traceback.print_exc()
        wait_sync()
    finally:
        if session:
            await session.close()
        sys.exit(0)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)
    
    try:
        print(f"{c['y']}Peringatan: Simbol 'OCTRA' menggunakan BIP44 coin type Ethereum sebagai fallback ({OCTRA.BIP44_COIN_TYPE}). Mohon verifikasi coin type Octra yang benar.{c['r']}")
        sys.stdout.flush()
    except Exception as e:
        print(f"{c['y']}Peringatan umum saat menyiapkan HDWallet: {e}. Fungsi seed mungkin terpengaruh.{c['r']}")
        sys.stdout.flush()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{c['y']}Keluar...{c['r']}")
        pass
    except Exception:
        pass
    finally:
        cls()
        print(f"{c['r']}")
