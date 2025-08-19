import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext
import base64, binascii, secrets, re

from gostcrypto import gosthash, gostsignature, gostcipher

# GOST R 34.10-2012 elliptic curve parameter sets
CURVE_256 = gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
CURVE_512 = gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-512-paramSetA']


def hexlify(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def unhex(s: str) -> bytes:
    s = s.strip().replace(' ', '').replace('\n', '')
    if s.startswith('0x'):
        s = s[2:]
    try:
        return binascii.unhexlify(s)
    except binascii.Error as e:
        raise ValueError(f'Invalid hex: {e}')


def streebog_digest(data: bytes, bits: int) -> bytes:
    h = gosthash.new(f"streebog{bits}", data=data)
    return h.digest()


def genkey(bits: int):
    curve = CURVE_256 if bits == 256 else CURVE_512
    m = gostsignature.MODE_256 if bits == 256 else gostsignature.MODE_512
    signer = gostsignature.new(m, curve)
    q = int(curve['q'])
    nbytes = 32 if bits == 256 else 64
    while True:
        d = (secrets.randbits(nbytes*8) % (q-1)) + 1
        if 1 <= d < q:
            prv = d.to_bytes(nbytes, 'big')
            break
    pub = signer.public_key_generate(prv)
    return hexlify(prv), hexlify(pub)


def sign_message(bits: int, priv_hex: str, msg: bytes) -> str:
    curve = CURVE_256 if bits == 256 else CURVE_512
    m = gostsignature.MODE_256 if bits == 256 else gostsignature.MODE_512
    signer = gostsignature.new(m, curve)
    digest = streebog_digest(msg, bits)
    sig = signer.sign(unhex(priv_hex), digest)
    return hexlify(sig)


def verify_message(bits: int, pub_hex: str, sig_hex: str, msg: bytes) -> bool:
    curve = CURVE_256 if bits == 256 else CURVE_512
    m = gostsignature.MODE_256 if bits == 256 else gostsignature.MODE_512
    verifier = gostsignature.new(m, curve)
    digest = streebog_digest(msg, bits)
    return verifier.verify(unhex(pub_hex), digest, unhex(sig_hex))


def encrypt(alg_key: str, key_hex: str, iv_hex: str, data: bytes) -> str:
    alg = 'kuznechik' if alg_key == 'kuz' else 'magma'
    key = bytearray(unhex(key_hex))
    iv = bytearray(unhex(iv_hex))
    if len(key) != 32:
        raise ValueError('Key must be 32 bytes (256-bit) in hex')
    if len(iv) != 8:
        raise ValueError('IV must be 8 bytes (64-bit) in hex for CTR mode')
    c = gostcipher.new(alg, key, gostcipher.MODE_CTR, init_vect=iv)
    ct = c.encrypt(bytearray(data))
    return base64.b64encode(bytes(ct)).decode()


def decrypt(alg_key: str, key_hex: str, iv_hex: str, b64_text: str) -> bytes:
    alg = 'kuznechik' if alg_key == 'kuz' else 'magma'
    key = bytearray(unhex(key_hex))
    iv = bytearray(unhex(iv_hex))
    b64_clean = re.sub(r'\s+', '', b64_text)
    raw = base64.b64decode(b64_clean, validate=True)
    c = gostcipher.new(alg, key, gostcipher.MODE_CTR, init_vect=iv)
    return bytes(c.decrypt(bytearray(raw)))

# UI setup
class CopyBox(ttk.Frame):
    def __init__(self, master, label: str, multiline=False, height=4, **kw):
        super().__init__(master, **kw)
        self.label = ttk.Label(self, text=label)
        self.label.pack(anchor='w')
        if multiline:
            self.text = scrolledtext.ScrolledText(self, height=height, wrap='word')
            self.text.pack(fill='x')
        else:
            self.text = ttk.Entry(self)
            self.text.pack(fill='x')
        btns = ttk.Frame(self)
        btns.pack(anchor='e', pady=3)
        self.copy_btn = ttk.Button(btns, text='Copy', command=self.copy)
        self.copy_btn.pack(side='right')

    def set(self, value: str):
        if isinstance(self.text, ttk.Entry):
            self.text.delete(0, 'end')
            self.text.insert(0, value)
        else:
            self.text.delete('1.0', 'end')
            self.text.insert('1.0', value)

    def get(self) -> str:
        if isinstance(self.text, ttk.Entry):
            return self.text.get()
        return self.text.get('1.0', 'end').strip()

    def copy(self):
        v = self.get()
        self.clipboard_clear()
        self.clipboard_append(v)


def file_to_bytes(parent) -> bytes | None:
    path = filedialog.askopenfilename(parent=parent, title='Select file to load')
    if not path:
        return None
    with open(path, 'rb') as f:
        return f.read()

# UI
root = tk.Tk()
root.title('GOST Crypto Toolkit (Local)')
root.geometry('820x700')

style = ttk.Style(root)
try:
    style.theme_use('vista')
except Exception:
    pass

nb = ttk.Notebook(root)
nb.pack(expand=True, fill='both', padx=10, pady=10)

_sign_binary_payload = None
_enc_binary_plain = None

# Intro tab
intro = ttk.Frame(nb)
nb.add(intro, text='Introduction')
intro_text = (
    "This is a local GOST toolkit.\n\n"
    "Tabs overview:\n"
    "• Hash — Convert contents of text or file to GOST R 34.11-2012 (256/512).\n"
    "• Keygen — Generate GOST 34.10-2012 keypairs. Keys appear below with copy buttons.\n"
    "• Sign/Verify — Sign text with a private key; verify with public key. Hashes the content first.\n"
    "• Encrypt/Decrypt — Kuznechik/Magma in CTR mode. Key=32 bytes hex; IV=8 bytes hex.\n\n"
    "Notes:\n"
    "• This app is local-only.\n"
    "• CTR requires a unique IV per encryption with the same key.\n"
)
intro_box = scrolledtext.ScrolledText(intro, height=18, wrap='word')
intro_box.pack(expand=True, fill='both')
intro_box.insert('1.0', intro_text)
intro_box.configure(state='disabled')

def set_status(msg, ms=2500):
    status.set(msg)
    root.after(ms, lambda: status.set("Ready"))

# Hash tab
hash_tab = ttk.Frame(nb)
nb.add(hash_tab, text='Hash')

hash_bits = tk.IntVar(value=256)
rb_row = ttk.Frame(hash_tab); rb_row.pack(anchor='w', pady=4)
for b in (256, 512):
    ttk.Radiobutton(rb_row, text=str(b), variable=hash_bits, value=b).pack(side='left')

hash_input = CopyBox(hash_tab, 'Input text', multiline=True, height=6)
hash_input.pack(fill='x', pady=4)

hash_output = CopyBox(hash_tab, 'Digest (hex)', multiline=True, height=3)
hash_output.pack(fill='x', pady=4)

hash_btns = ttk.Frame(hash_tab); hash_btns.pack(anchor='w', pady=4)

def do_hash():
    data = hash_input.get().encode()
    d = streebog_digest(data, hash_bits.get())
    hash_output.set(hexlify(d))
    set_status("Hashing successful")

def do_hash_file():
    data = file_to_bytes(hash_tab)
    if data is None:
        return
    d = streebog_digest(data, hash_bits.get())
    hash_output.set(hexlify(d))
    set_status("Hashing successful")

ttk.Button(hash_btns, text='Convert Text', command=do_hash).pack(side='left', padx=5)
ttk.Button(hash_btns, text='Alt: Convert File…', command=do_hash_file).pack(side='left', padx=5)

# Keygen tab
key_tab = ttk.Frame(nb)
nb.add(key_tab, text='Keygen')

kg_bits = tk.IntVar(value=256)
rbkg = ttk.Frame(key_tab); rbkg.pack(anchor='w', pady=4)
for b in (256, 512):
    ttk.Radiobutton(rbkg, text=str(b), variable=kg_bits, value=b).pack(side='left')

priv_box = CopyBox(key_tab, 'Private key (hex)')
priv_box.pack(fill='x', pady=4)

pub_box = CopyBox(key_tab, 'Public key (hex)', multiline=True, height=3)
pub_box.pack(fill='x', pady=4)


def do_keygen():
    prv, pub = genkey(kg_bits.get())
    priv_box.set(prv)
    pub_box.set(pub)
    set_status("Key generation successful")

kg_btns = ttk.Frame(key_tab); kg_btns.pack(anchor='w', pady=4)

# Save keys to files

def save_keypair():
    prv = priv_box.get().strip()
    pub = pub_box.get().strip()
    if not prv or not pub:
        return
    base = filedialog.asksaveasfilename(parent=key_tab, defaultextension='.txt', title='Save keypair as…', initialfile='gost_keypair')
    if not base:
        return
    with open(base, 'w', encoding='utf-8') as f:
        f.write('PRIVATE (hex)\n' + prv + '\n\nPUBLIC (hex)\n' + pub + '\n')

ttk.Button(kg_btns, text='Generate Keypair', command=do_keygen).pack(side='left', padx=5)
ttk.Button(kg_btns, text='Save Keypair…', command=save_keypair).pack(side='left', padx=5)

# Sign / Verify tab
sig_tab = ttk.Frame(nb)
nb.add(sig_tab, text='Sign / Verify')

sv_bits = tk.IntVar(value=256)
rbsv = ttk.Frame(sig_tab); rbsv.pack(anchor='w', pady=4)
for b in (256, 512):
    ttk.Radiobutton(rbsv, text=str(b), variable=sv_bits, value=b).pack(side='left')

sign_msg = CopyBox(sig_tab, 'Message to sign / verify', multiline=True, height=6)
sign_msg.pack(fill='x', pady=4)

priv_in = CopyBox(sig_tab, 'Private key for signing (hex)')
priv_in.pack(fill='x', pady=2)

pub_in = CopyBox(sig_tab, 'Public key for verifying (hex)', multiline=True, height=3)
pub_in.pack(fill='x', pady=2)

sig_out = CopyBox(sig_tab, 'Signature (hex)', multiline=True, height=3)
sig_out.pack(fill='x', pady=4)

sv_btns = ttk.Frame(sig_tab); sv_btns.pack(anchor='w', pady=4)

def sig_only(s: str) -> str:
    for line in reversed(s.splitlines()):
        t = line.strip()
        if t and all(c in "0123456789abcdefABCDEF" for c in t):
            return t
    return s.strip()


def do_sign():
    global _sign_binary_payload
    try:
        msg_bytes = sign_msg.get().encode()
        sig = sign_message(sv_bits.get(), priv_in.get(), msg_bytes)  # sv_bits not sg_bits
        sig_out.set(sig)
        _sign_binary_payload = msg_bytes
        set_status("Signature successful")
    except Exception as e:
        sig_out.set(f'ERROR: {e}')
        set_status("Signature error")


def do_verify():
    global _sign_binary_payload
    try:
        msg_bytes = _sign_binary_payload if _sign_binary_payload is not None else sign_msg.get().encode()
        sig_hex = sig_only(sig_out.get())
        ok = verify_message(sv_bits.get(), pub_in.get(), sig_hex, msg_bytes)
        sig_out.set(('✓ VALID\n' if ok else '✗ INVALID\n') + sig_hex)
        set_status("Verification successful" if ok else "Verification failed")
    except Exception as e:
        sig_out.set(f'ERROR: {e}')
        set_status("Verification error")

# Load from file helper for message

def load_msg_from_file():
    global _sign_binary_payload
    data = file_to_bytes(sig_tab)
    if data is None:
        return
    try:
        sign_msg.set(data.decode('utf-8'))
        _sign_binary_payload = None
    except UnicodeDecodeError:
        _sign_binary_payload = data
        sign_msg.set(f'<binary data loaded: {len(data)} bytes>')

ttk.Button(sv_btns, text='Load Message from File…', command=load_msg_from_file).pack(side='left', padx=5)
ttk.Button(sv_btns, text='Sign', command=do_sign).pack(side='left', padx=5)
ttk.Button(sv_btns, text='Verify', command=do_verify).pack(side='left', padx=5)

# Encrypt / Decrypt tab
enc_tab = ttk.Frame(nb)
nb.add(enc_tab, text='Encrypt / Decrypt')

alg_var = tk.StringVar(value='kuz')
rb_alg = ttk.Frame(enc_tab); rb_alg.pack(anchor='w', pady=4)
for label, val in (('Kuznechik', 'kuz'), ('Magma', 'magma')):
    ttk.Radiobutton(rb_alg, text=label, variable=alg_var, value=val).pack(side='left')

key_in = CopyBox(enc_tab, 'Key (hex, 32 bytes)')
key_in.pack(fill='x', pady=2)

iv_in = CopyBox(enc_tab, 'IV (hex, 8 bytes)')
iv_in.pack(fill='x', pady=2)

pt_in = CopyBox(enc_tab, 'Plaintext', multiline=True, height=6)
pt_in.pack(fill='x', pady=4)

ct_out = CopyBox(enc_tab, 'Ciphertext (base64)', multiline=True, height=4)
ct_out.pack(fill='x', pady=4)

enc_btns = ttk.Frame(enc_tab); enc_btns.pack(anchor='w', pady=4)


def gen_sym():
    key = hexlify(secrets.token_bytes(32))
    iv = hexlify(secrets.token_bytes(8))
    key_in.set(key)
    iv_in.set(iv)


def do_encrypt():
    global _enc_binary_plain
    try:
        plain = _enc_binary_plain if _enc_binary_plain is not None else pt_in.get().encode()
        ct = encrypt(alg_var.get(), key_in.get(), iv_in.get(), plain)
        ct_out.set(ct)
        set_status("Encryption successful")
    except Exception as e:
        ct_out.set(f'ERROR: {e}')
        set_status("Encryption error")


def do_decrypt():
    try:
        pt = decrypt(alg_var.get(), key_in.get(), iv_in.get(), ct_out.get())
        pt_in.set(pt.decode(errors="replace"))
        set_status("Decryption successful")
    except Exception as e:
        ct_out.set(f'ERROR: {e}')
        set_status("Decryption error")


def load_plain_from_file():
    global _enc_binary_plain
    data = file_to_bytes(enc_tab)
    if data is None:
        return
    try:
        pt_in.set(data.decode('utf-8'))
        _enc_binary_plain = None
    except UnicodeDecodeError:
        _enc_binary_plain = data
        pt_in.set(f'<binary data loaded: {len(data)} bytes>')


def save_cipher_to_file():
    b64 = ct_out.get().strip()
    if not b64:
        return
    path = filedialog.asksaveasfilename(parent=enc_tab, title='Save ciphertext (base64) as…', defaultextension='.txt', initialfile='ciphertext')
    if not path:
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write(b64)


def copy_unique_iv():
    iv_in.set(hexlify(secrets.token_bytes(8)))


def copy_unique_key():
    key_in.set(hexlify(secrets.token_bytes(32)))


# Buttons
ttk.Button(enc_btns, text='Generate Key+IV', command=gen_sym).pack(side='left', padx=5)
ttk.Button(enc_btns, text='New Key', command=copy_unique_key).pack(side='left', padx=5)
ttk.Button(enc_btns, text='New IV', command=copy_unique_iv).pack(side='left', padx=5)
ttk.Button(enc_btns, text='Load Plaintext…', command=load_plain_from_file).pack(side='left', padx=5)
ttk.Button(enc_btns, text='Encrypt →', command=do_encrypt).pack(side='left', padx=5)
ttk.Button(enc_btns, text='← Decrypt', command=do_decrypt).pack(side='left', padx=5)

# Status bar
status = tk.StringVar(value='Ready')
bar = ttk.Label(root, textvariable=status, relief='sunken', anchor='w')
bar.pack(fill='x', side='bottom')

root.mainloop()
