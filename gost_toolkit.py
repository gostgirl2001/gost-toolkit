import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext
import base64, binascii, secrets, re
import subprocess, tempfile, os
from typing import Optional, List, Dict

# GOST backend
try:
    from gostcrypto import gosthash, gostsignature, gostcipher
except ModuleNotFoundError:
    raise SystemExit(
        "Missing dependency: 'gostcrypto'.\n"
        "Install it with:\n"
        "  python3 -m pip install gostcrypto==1.2.5"
    )

CURVE_256 = gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
CURVE_512 = gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-512-paramSetA']

def hexlify(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def unhex(s: str) -> bytes:
    s = s.strip().replace(' ', '').replace('\n', '')
    if s.startswith('0x'):
        s = s[2:]
    return binascii.unhexlify(s)

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
    b64_clean = re.sub(r'\s+', '', b64_text)
    raw = base64.b64decode(b64_clean, validate=True)
    alg = 'kuznechik' if alg_key == 'kuz' else 'magma'
    key = bytearray(unhex(key_hex))
    iv = bytearray(unhex(iv_hex))
    c = gostcipher.new(alg, key, gostcipher.MODE_CTR, init_vect=iv)
    return bytes(c.decrypt(bytearray(raw)))

# OpenSSL CMS helpers
def _run(cmd: List[str], data: Optional[bytes] = None, env: Optional[Dict[str,str]] = None) -> str:
    p = subprocess.Popen(
        cmd, stdin=subprocess.PIPE if data else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or os.environ.copy()
    )
    out, err = p.communicate(data)
    if p.returncode != 0:
        raise RuntimeError((err or out).decode(errors='replace'))
    return out.decode(errors='replace')

def _is_pem(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(16).startswith(b'-----BEGIN ')
    except:
        return False

def cms_sign(data: bytes, cert_path: str, key_path: str, out_path: str,
             detached: bool, use_512: bool = False,
             key_password: Optional[str] = None,
             include_chain_from: Optional[str] = None) -> str:
    md = "md_gost12_512" if use_512 else "md_gost12_256"
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(data); tmp_in.flush(); in_path = tmp_in.name
    cmd = [
        "openssl", "cms", "-sign", "-engine", "gost",
        "-binary", "-md", md, "-in", in_path,
        "-signer", cert_path, "-inkey", key_path,
        "-outform", "DER", "-nosmimecap"
    ]
    if include_chain_from:
        cmd += ["-certfile", include_chain_from]
    if detached:
        cmd.append("-detached")
        if not out_path.lower().endswith(".p7s"): out_path += ".p7s"
    else:
        cmd.append("-nodetach")
        if not out_path.lower().endswith(".p7m"): out_path += ".p7m"
    env = os.environ.copy()
    if key_password:
        cmd += ["-passin", "env:SIG_PASS"]; env["SIG_PASS"] = key_password
    try:
        cmd += ["-out", out_path]; _run(cmd, env=env); return out_path
    finally:
        try: os.unlink(in_path)
        except: pass

def cms_verify(sig_path: str, data_path_detached: Optional[str] = None,
               ca_file: Optional[str] = None) -> dict:
    verify_cmd = ["openssl","cms","-verify","-engine","gost",
                  "-inform","DER","-binary","-in",sig_path]
    if sig_path.lower().endswith(".p7s"):
        if not data_path_detached:
            raise ValueError("Detached signature requires original data.")
        verify_cmd += ["-content", data_path_detached]
    verify_cmd += ["-noverify"]
    _run(verify_cmd)
    chain_ok, chain_message = True, ""
    if ca_file:
        vc = ["openssl","cms","-verify","-engine","gost",
              "-inform","DER","-binary","-in",sig_path,"-CAfile",ca_file]
        if sig_path.lower().endswith(".p7s"):
            vc += ["-content", data_path_detached]
        try: _run(vc)
        except Exception as e: chain_ok, chain_message = False, str(e)
    info = _run(["openssl","cms","-cmsout","-inform","DER","-in",sig_path,"-print"])
    subject=issuer=serial=digest=signing_time=None
    for line in info.splitlines():
        t=line.strip()
        if t.startswith("subject:"): subject=t.split("subject:",1)[1].strip()
        elif t.startswith("issuer:"): issuer=t.split("issuer:",1)[1].strip()
        elif t.startswith("serial:"): serial=t.split("serial:",1)[1].strip()
        elif "digestAlgorithm:" in t: digest=t.split(":",1)[1].strip()
        elif "signingTime:" in t: signing_time=t.split(":",1)[1].strip()
    return {
        "ok": True, "chain_ok": chain_ok, "chain_message": chain_message,
        "signer_info": {"subject":subject,"issuer":issuer,"serial":serial,
                        "digest":digest,"signingTime":signing_time},
        "raw_print": info,
    }

TC26_OIDS = {
    "1.2.643.7.1.1.1.1":"id-tc26-gost3410-2012-256",
    "1.2.643.7.1.1.1.2":"id-tc26-gost3410-2012-512",
    "1.2.643.7.1.1.2.2":"id-tc26-gost3411-2012-256",
    "1.2.643.7.1.1.2.3":"id-tc26-gost3411-2012-512",
    "1.2.643.7.1.1.3.2":"id-tc26-signwithdigest-gost3410-2012-256",
    "1.2.643.7.1.1.3.3":"id-tc26-signwithdigest-gost3410-2012-512",
}

def cert_show_oids(cert_path: str) -> str:
    inform="PEM" if _is_pem(cert_path) else "DER"
    dump=_run(["openssl","asn1parse","-in",cert_path,"-inform",inform,"-i"])
    found: Dict[str,str] = {}
    for line in dump.splitlines():
        if "OBJECT" in line and "1.2.643.7.1.1." in line:
            oid=line.split("OBJECT:")[-1].split()[0]
            found[oid]=TC26_OIDS.get(oid,"(unknown TC26)")
    if not found: return "No TC26 OIDs found."
    return "Detected TC26 OIDs:\n"+"\n".join(f"  {k} — {v}" for k,v in found.items())

def cert_pem_to_der(in_path: str, out_path: str) -> str:
    _run(["openssl","x509","-in",in_path,"-inform","PEM","-out",out_path,"-outform","DER"]); return out_path

def cert_der_to_pem(in_path: str, out_path: str) -> str:
    _run(["openssl","x509","-in",in_path,"-inform","DER","-out",out_path,"-outform","PEM"]); return out_path

def key_pem_to_der_pkcs8(in_path: str, out_path: str, password: Optional[str] = None) -> str:
    cmd=["openssl","pkcs8","-topk8","-nocrypt","-in",in_path,"-out",out_path,"-outform","DER"]; env=None
    if password: cmd=["openssl","pkcs8","-topk8","-in",in_path,"-passin","env:KEY_PASS",
                      "-out",out_path,"-outform","DER","-nocrypt"]; env=os.environ.copy(); env["KEY_PASS"]=password
    _run(cmd,env=env); return out_path

def key_der_to_pem_pkcs8(in_path: str, out_path: str, password: Optional[str] = None) -> str:
    cmd=["openssl","pkcs8","-inform","DER","-in",in_path,"-out",out_path,"-outform","PEM"]; env=None
    if password: cmd+=["-passin","env:KEY_PASS"]; env=os.environ.copy(); env["KEY_PASS"]=password
    _run(cmd,env=env); return out_path

# UI scaffolding
root = tk.Tk()
root.title('GOST Crypto Toolkit (Local)')
root.geometry('1000x860')

style = ttk.Style(root)
try:
    style.theme_use('vista')
except Exception:
    pass

nb = ttk.Notebook(root)
nb.pack(expand=True, fill='both', padx=10, pady=10)

_sign_binary_payload: Optional[bytes] = None
_enc_binary_plain: Optional[bytes] = None

def set_status(msg, ms=2500):
    status.set(msg)
    root.after(ms, lambda: status.set("Ready"))

def file_to_bytes(parent) -> Optional[bytes]:
    path = filedialog.askopenfilename(parent=parent, title='Select file to load')
    if not path:
        return None
    with open(path, 'rb') as f:
        return f.read()

# Round radio buttons
def round_radio(parent, text, variable, value):
    rb = tk.Radiobutton(parent, text=text, variable=variable, value=value, anchor='w')
    rb.configure(indicatoron=1)
    return rb

# File picker
class FilePicker(ttk.Frame):
    def __init__(self, master, label: str, must_exist=True, filetypes=(("All files","*.*"),), **kw):
        super().__init__(master, **kw)
        self.must_exist = must_exist
        self.filetypes = filetypes
        self._path = tk.StringVar(value="")
        row = ttk.Frame(self); row.pack(fill='x', pady=2)
        ttk.Label(row, text=label).pack(side='left')
        ttk.Button(row, text="Select…", command=self._browse).pack(side='right')
        self.path_label = ttk.Label(self, textvariable=self._path, relief='sunken', anchor='w')
        self.path_label.pack(fill='x', padx=0, pady=2)
    def _browse(self):
        if self.must_exist:
            p = filedialog.askopenfilename(parent=self, title="Select file", filetypes=self.filetypes)
        else:
            p = filedialog.asksaveasfilename(parent=self, title="Select output file", filetypes=self.filetypes)
        if p:
            self._path.set(p)
    def get_path(self) -> str:
        return self._path.get().strip()
    def set_path(self, path: str):
        self._path.set(path)

class CopyBox(ttk.Frame):
    def __init__(self, master, label: str, multiline: bool=False, height: int=4, password: bool=False, **kw):
        super().__init__(master, **kw)
        self.label = ttk.Label(self, text=label)
        self.label.pack(anchor='w')
        self.multiline = multiline
        if multiline:
            self.text = scrolledtext.ScrolledText(self, height=height, wrap='word')
            self.text.pack(fill='x')
        else:
            self.text = ttk.Entry(self, show="*" if password else None)
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

# Intro tab
intro = ttk.Frame(nb)
nb.add(intro, text='Introduction')
intro_text = (
    "This is a local GOST toolkit.\n\n"
    "Tabs overview:\n"
    "• Hash — Convert contents of text or file to GOST R 34.11-2012 (256/512).\n"
    "• Keygen — Generate GOST 34.10-2012 keypairs.\n"
    "• Sign/Verify — Sign text with a private key; verify with public key. Hashes the content first.\n"
    "• Encrypt/Decrypt — Kuznechik/Magma in CTR mode. Key=32 bytes hex; IV=8 bytes hex.\n"
    "• PKCS#7 Sign / Verify — CAdES-BES signing/verification with GOST-enabled OpenSSL.\n"
    "• PKCS#7 Tools — OID scan, PEM<->DER conversions.\n\n"
    "Notes:\n"
    "• This app is local-only.\n"
    "• Secure CTR requires a unique IV per encryption with the same key.\n"
)
intro_box = scrolledtext.ScrolledText(intro, height=16, wrap='word')
intro_box.pack(expand=True, fill='both')
intro_box.insert('1.0', intro_text)
intro_box.configure(state='disabled')

# Hash tab
hash_tab = ttk.Frame(nb)
nb.add(hash_tab, text='Hash')

hash_bits = tk.IntVar(value=256)
rb_row = ttk.Frame(hash_tab); rb_row.pack(anchor='w', pady=4)
for b in (256, 512):
    round_radio(rb_row, str(b), hash_bits, b).pack(side='left', padx=(0,10))

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
    round_radio(rbkg, str(b), kg_bits, b).pack(side='left', padx=(0,10))

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

def save_keypair():
    prv = priv_box.get().strip()
    pub = pub_box.get().strip()
    if not prv or not pub:
        return
    base = filedialog.asksaveasfilename(parent=key_tab, defaultextension='.txt',
                                        title='Save keypair as…', initialfile='gost_keypair')
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
    round_radio(rbsv, str(b), sv_bits, b).pack(side='left', padx=(0,10))

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
        sig = sign_message(sv_bits.get(), priv_in.get(), msg_bytes)
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
    round_radio(rb_alg, label, alg_var, val).pack(side='left', padx=(0,10))

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
    path = filedialog.asksaveasfilename(parent=enc_tab, title='Save ciphertext (base64) as…',
                                        defaultextension='.txt', initialfile='ciphertext')
    if not path:
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write(b64)

def copy_unique_iv():
    iv_in.set(hexlify(secrets.token_bytes(8)))

def copy_unique_key():
    key_in.set(hexlify(secrets.token_bytes(32)))

ttk.Button(enc_btns, text='Generate Key+IV', command=gen_sym).pack(side='left', padx=5)
ttk.Button(enc_btns, text='New Key', command=copy_unique_key).pack(side='left', padx=5)
ttk.Button(enc_btns, text='New IV', command=copy_unique_iv).pack(side='left', padx=5)
ttk.Button(enc_btns, text='Load Plaintext…', command=load_plain_from_file).pack(side='left', padx=5)
ttk.Button(enc_btns, text='Encrypt →', command=do_encrypt).pack(side='left', padx=5)
ttk.Button(enc_btns, text='← Decrypt', command=do_decrypt).pack(side='left', padx=5)

# PKCS#7 Sign (CMS) — separate tab
cms_sign_tab = ttk.Frame(nb)
nb.add(cms_sign_tab, text='PKCS#7 Sign')

cms_data_fp  = FilePicker(cms_sign_tab, 'Data file to be signed', filetypes=(("All files","*.*"),))
cms_cert_fp  = FilePicker(cms_sign_tab, 'Signer certificate (PEM/DER)',
                          filetypes=(("Cert files","*.pem *.cer *.crt *.der"),("All files","*.*")))
cms_key_fp   = FilePicker(cms_sign_tab, 'Signer private key (PEM/DER/PKCS#8)',
                          filetypes=(("Key files","*.pem *.key *.der *.p8"),("All files","*.*")))
cms_chain_fp = FilePicker(cms_sign_tab, '(Optional: Embed CA chain from PEM file',
                          filetypes=(("PEM files","*.pem"),("All files","*.*")))
for w in (cms_data_fp, cms_cert_fp, cms_key_fp, cms_chain_fp):
    w.pack(fill='x', pady=2)

row_opt = ttk.Frame(cms_sign_tab); row_opt.pack(anchor='w', pady=6)
dgst_bits = tk.IntVar(value=256)
round_radio(row_opt, 'GOST 2012 256-bit', dgst_bits, 256).pack(side='left', padx=(0,10))
round_radio(row_opt, '512-bit', dgst_bits, 512).pack(side='left', padx=(0,10))

key_pass_box = CopyBox(cms_sign_tab, 'Private key password (if required)', password=True)
key_pass_box.pack(fill='x', pady=2)

cms_sign_out = CopyBox(cms_sign_tab, 'Output / Status', multiline=True, height=12)
cms_sign_out.pack(fill='both', expand=True, pady=8)

def _do_cms_sign(detached: bool):
    try:
        data_path = cms_data_fp.get_path()
        cert_path = cms_cert_fp.get_path()
        key_path  = cms_key_fp.get_path()
        chain_path = cms_chain_fp.get_path() or None
        if not (data_path and cert_path and key_path):
            cms_sign_out.set("ERROR: select data, signer certificate, and private key files.")
            return
        with open(data_path, 'rb') as f:
            data = f.read()
        base = os.path.splitext(data_path)[0]
        out_guess = base + (".p7s" if detached else ".p7m")
        out_path = filedialog.asksaveasfilename(parent=cms_sign_tab,
                        title='Save signature as…',
                        defaultextension=(".p7s" if detached else ".p7m"),
                        initialfile=os.path.basename(out_guess),
                        filetypes=(("CMS/PKCS#7","*.p7s *.p7m"),("All files","*.*")))
        if not out_path:
            cms_sign_out.set("Cancelled.")
            return
        saved = cms_sign(
            data, cert_path, key_path, out_path,
            detached=detached,
            use_512=(dgst_bits.get()==512),
            key_password=(key_pass_box.get().strip() or None),
            include_chain_from=chain_path
        )
        mode = "DETACHED (.p7s)" if detached else "ATTACHED (.p7m)"
        md = "md_gost12_512" if dgst_bits.get()==512 else "md_gost12_256"
        cms_sign_out.set(f"✓ Signed [{mode}, {md}]\nSaved: {saved}")
        set_status("CMS signing successful")
    except Exception as e:
        cms_sign_out.set(f"✗ CMS sign error:\n{e}")
        set_status("CMS signing error")

btn_row = ttk.Frame(cms_sign_tab); btn_row.pack(anchor='w', pady=6)
ttk.Button(btn_row, text='Sign (Detached .p7s) →', command=lambda: _do_cms_sign(True)).pack(side='left', padx=8)
ttk.Button(btn_row, text='Sign (Attached .p7m) →', command=lambda: _do_cms_sign(False)).pack(side='left', padx=8)

# PKCS#7 Verify (CMS)
cms_verify_tab = ttk.Frame(nb)
nb.add(cms_verify_tab, text='PKCS#7 Verify')

cms_sig_fp   = FilePicker(cms_verify_tab, 'Signature file (.p7m or .p7s)',
                          filetypes=(("CMS/PKCS#7","*.p7m *.p7s"),("All files","*.*")))
cms_sig_fp.pack(fill='x', pady=2)

cms_det_fp   = FilePicker(cms_verify_tab, 'Original data (required for .p7s)',
                          filetypes=(("All files","*.*"),))
cms_det_fp.pack(fill='x', pady=2)

cms_ca_fp    = FilePicker(cms_verify_tab, '(Optional) Embed CA bundle for chain verification (PEM file)',
                          filetypes=(("PEM files","*.pem"),("All files","*.*")))
cms_ca_fp.pack(fill='x', pady=2)

cms_verify_out = CopyBox(cms_verify_tab, 'Verification Output', multiline=True, height=14)
cms_verify_out.pack(fill='both', expand=True, pady=8)

def do_cms_verify():
    try:
        sig_path = cms_sig_fp.get_path()
        if not sig_path:
            cms_verify_out.set("ERROR: select a .p7m or .p7s file.")
            return
        data_path = cms_det_fp.get_path() or None
        ca_path = cms_ca_fp.get_path() or None
        if sig_path.lower().endswith(".p7s") and not data_path:
            cms_verify_out.set("ERROR: detached .p7s requires original data file.")
            return
        res = cms_verify(sig_path, data_path, ca_path)
        info = res.get("signer_info", {})
        lines = [
            "✓ Syntactic verification OK.",
            f"Chain OK: {res['chain_ok']}" + ("" if res['chain_ok'] else f" — {res['chain_message']}"),
            "",
            "[Signer]",
            f"Subject: {info.get('subject')}",
            f"Issuer : {info.get('issuer')}",
            f"Serial : {info.get('serial')}",
            f"Digest : {info.get('digest')}",
            f"Time   : {info.get('signingTime')}",
        ]
        cms_verify_out.set("\n".join(lines))
        set_status("CMS verification complete")
    except Exception as e:
        cms_verify_out.set(f"✗ CMS verify error:\n{e}")
        set_status("CMS verification error")

btn_row_v = ttk.Frame(cms_verify_tab); btn_row_v.pack(anchor='w', pady=6)
ttk.Button(btn_row_v, text='← Verify', command=do_cms_verify).pack(side='left', padx=8)

# PKCS#7 Tools — OIDs / DER conversions
cms_tools_tab = ttk.Frame(nb)
nb.add(cms_tools_tab, text='PKCS#7 Tools')

tools_info = ttk.Label(cms_tools_tab, text='OID scan and PEM<->DER conversions')
tools_info.pack(anchor='w', pady=(8,4))

tools_buttons = ttk.Frame(cms_tools_tab); tools_buttons.pack(anchor='w', pady=2)

tools_out = CopyBox(cms_tools_tab, 'Output / Status', multiline=True, height=14)
tools_out.pack(fill='both', expand=True, pady=8)

def do_show_oids():
    path = filedialog.askopenfilename(parent=cms_tools_tab, title='Select certificate (PEM/DER)',
                                      filetypes=(("Cert files","*.pem *.cer *.crt *.der"),("All files","*.*")))
    if not path: return
    try:
        tools_out.set(cert_show_oids(path))
        set_status("OIDs extracted")
    except Exception as e:
        tools_out.set(f"✗ OID parse error:\n{e}")
        set_status("OIDs error")

def do_cert_to_der():
    inp = filedialog.askopenfilename(parent=cms_tools_tab, title='Select certificate (PEM)',
                                     filetypes=(("PEM files","*.pem"),("All files","*.*")))
    if not inp: return
    out = filedialog.asksaveasfilename(parent=cms_tools_tab, title='Save DER cert as…',
                                       defaultextension='.der', initialfile='cert.der',
                                       filetypes=(("DER files","*.der"),("All files","*.*")))
    if not out: return
    try:
        tools_out.set("Saved: " + cert_pem_to_der(inp, out))
        set_status("Cert → DER saved")
    except Exception as e:
        tools_out.set(f"✗ Convert error:\n{e}")

def do_cert_to_pem():
    inp = filedialog.askopenfilename(parent=cms_tools_tab, title='Select certificate (DER)',
                                     filetypes=(("DER files","*.der"),("All files","*.*")))
    if not inp: return
    out = filedialog.asksaveasfilename(parent=cms_tools_tab, title='Save PEM cert as…',
                                       defaultextension='.pem', initialfile='cert.pem',
                                       filetypes=(("PEM files","*.pem"),("All files","*.*")))
    if not out: return
    try:
        tools_out.set("Saved: " + cert_der_to_pem(inp, out))
        set_status("Cert → PEM saved")
    except Exception as e:
        tools_out.set(f"✗ Convert error:\n{e}")

def do_key_to_der():
    inp = filedialog.askopenfilename(parent=cms_tools_tab, title='Select private key (PEM/PKCS#8 PEM)',
                                     filetypes=(("Key files","*.pem *.key"),("All files","*.*")))
    if not inp: return
    out = filedialog.asksaveasfilename(parent=cms_tools_tab, title='Save PKCS#8 DER key as…',
                                       defaultextension='.der', initialfile='key.der',
                                       filetypes=(("DER files","*.der"),("All files","*.*")))
    if not out: return
    pwd = None
    if tk.messagebox.askyesno("Key password", "Is the input key encrypted with a password?"):
        # Simple prompt
        pw = tk.simpledialog.askstring("Key password", "Enter password:", show="*")
        pwd = pw or None
    try:
        tools_out.set("Saved: " + key_pem_to_der_pkcs8(inp, out, password=pwd))
        set_status("Key → DER saved")
    except Exception as e:
        tools_out.set(f"✗ Convert error:\n{e}")

def do_key_to_pem():
    inp = filedialog.askopenfilename(parent=cms_tools_tab, title='Select PKCS#8 DER key',
                                     filetypes=(("DER files","*.der"),("All files","*.*")))
    if not inp: return
    out = filedialog.asksaveasfilename(parent=cms_tools_tab, title='Save PKCS#8 PEM key as…',
                                       defaultextension='.pem', initialfile='key.pem',
                                       filetypes=(("PEM files","*.pem"),("All files","*.*")))
    if not out: return
    pwd = None
    if tk.messagebox.askyesno("Key password", "Is the input key encrypted with a password?"):
        pw = tk.simpledialog.askstring("Key password", "Enter password:", show="*")
        pwd = pw or None
    try:
        tools_out.set("Saved: " + key_der_to_pem_pkcs8(inp, out, password=pwd))
        set_status("Key → PEM saved")
    except Exception as e:
        tools_out.set(f"✗ Convert error:\n{e}")

ttk.Button(tools_buttons, text='Show Cert OIDs…', command=do_show_oids).pack(side='left', padx=4, pady=2)
ttk.Button(tools_buttons, text='Cert: PEM → DER…', command=do_cert_to_der).pack(side='left', padx=4, pady=2)
ttk.Button(tools_buttons, text='Cert: DER → PEM…', command=do_cert_to_pem).pack(side='left', padx=4, pady=2)
ttk.Button(tools_buttons, text='Key: PEM → DER (PKCS#8)…', command=do_key_to_der).pack(side='left', padx=4, pady=2)
ttk.Button(tools_buttons, text='Key: DER → PEM (PKCS#8)…', command=do_key_to_pem).pack(side='left', padx=4, pady=2)

# Status bar
status = tk.StringVar(value='Ready')
bar = ttk.Label(root, textvariable=status, relief='sunken', anchor='w')
bar.pack(fill='x', side='bottom')

root.mainloop()
