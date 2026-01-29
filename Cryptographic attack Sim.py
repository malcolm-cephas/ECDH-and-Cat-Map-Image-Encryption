
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import os
import binascii
from io import BytesIO

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
except Exception:
    raise SystemExit("Install pycryptodome: pip install pycryptodome")

try:
    from PIL import Image
    import numpy as np
except Exception:
    raise SystemExit("Install pillow and numpy: pip install pillow numpy")

try:
    from skimage.metrics import structural_similarity as compare_ssim
    HAVE_SKIMAGE = True
except Exception:
    HAVE_SKIMAGE = False

def is_image_bytes(b: bytes) -> bool:
    headers = [b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'BM']
    return any(b.startswith(h) for h in headers)

def auto_image_from_bytes(b: bytes):
    try:
        return Image.open(BytesIO(b))
    except Exception:
        return None

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def plausibility_score(candidate_bytes: bytes) -> float:
    score = 0.0
    if is_image_bytes(candidate_bytes):
        score += 0.7
    arr = np.frombuffer(candidate_bytes[:4096], dtype=np.uint8) if len(candidate_bytes) >= 16 else np.frombuffer(candidate_bytes, dtype=np.uint8)
    if arr.size == 0:
        return score
    hist = np.bincount(arr, minlength=256) / arr.size
    entropy = -np.sum([p * np.log2(p) for p in hist if p > 0])
    if entropy < 7.0:
        score += 0.2
    im = auto_image_from_bytes(candidate_bytes)
    if im is not None:
        score += 0.1
    return min(score, 1.0)

def local_encrypt(plaintext_bytes: bytes, key: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    return iv + ct

def local_decrypt(enc_bytes: bytes, key: bytes):
    if len(enc_bytes) < 16:
        raise ValueError("enc bytes too short")
    iv = enc_bytes[:16]
    ct = enc_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

class VulnerableOracle:
    def __init__(self, secret_key: bytes, deterministic_iv=False, timing_leak=False):
        self.secret_key = secret_key
        self.deterministic_iv = deterministic_iv
        self.timing_leak = timing_leak
        self.iv_fixed = get_random_bytes(16) if deterministic_iv else None

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = self.iv_fixed if self.deterministic_iv else get_random_bytes(16)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ct

    def decrypt(self, enc: bytes) -> bytes:
        if len(enc) < 16:
            raise ValueError("short")
        iv = enc[:16]
        ct = enc[16:]
        if self.timing_leak:
            bias = bin(self.secret_key[0]).count('1') * 0.0005
            time.sleep(bias)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt

def simulate_bruteforce(enc_bytes: bytes, keyspace_start: int, keyspace_end: int, progress_callback=None):
    found = []
    total = max(1, keyspace_end - keyspace_start + 1)
    for i, k in enumerate(range(keyspace_start, keyspace_end + 1)):
        key_candidate = (k).to_bytes(16, 'big', signed=False)
        try:
            pt = local_decrypt(enc_bytes, key_candidate)
            score = plausibility_score(pt)
            if score > 0.8:
                found.append((k, key_candidate, score))
        except Exception:
            pass
        if progress_callback:
            progress_callback(i + 1, total)
    return found

def simulate_cipher_only_analysis(enc_bytes: bytes, progress_callback=None):
    results = {}
    ct = enc_bytes
    results['length'] = len(ct)
    arr = np.frombuffer(ct, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256) / arr.size
    entropy = -np.sum([p * np.log2(p) for p in hist if p > 0])
    results['entropy'] = float(entropy)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    unique = len(set(blocks))
    results['blocks_total'] = len(blocks)
    results['blocks_unique'] = unique
    results['ecb_suspected'] = (unique < len(blocks) * 0.98)
    if progress_callback:
        progress_callback(1,1)
    return results

def simulate_known_plaintext(enc_bytes: bytes, known_plain_bytes: bytes, key_candidate: bytes=None):
    if key_candidate:
        try:
            pt = local_decrypt(enc_bytes, key_candidate)
            same = pt.startswith(known_plain_bytes[:min(len(pt), len(known_plain_bytes))])
            score = plausibility_score(pt)
            return {'match': same, 'score': score, 'plaintext_sample': pt[:64]}
        except Exception as e:
            return {'match': False, 'error': str(e)}
    else:
        results = []
        for k in range(0, 1 << 16):
            key = k.to_bytes(16, 'big')
            try:
                pt = local_decrypt(enc_bytes, key)
                if pt.startswith(known_plain_bytes[:min(len(pt), len(known_plain_bytes))]):
                    results.append((k, key))
                    break
            except Exception:
                pass
        return {'found': results}

def simulate_chosen_plaintext(oracle: VulnerableOracle, chosen_plain: bytes, progress_callback=None):
    ct = oracle.encrypt(chosen_plain)
    score = plausibility_score(ct)
    if progress_callback:
        progress_callback(1,1)
    return {'ciphertext': ct, 'plausibility': score}

def simulate_chosen_ciphertext(oracle: VulnerableOracle, chosen_cipher: bytes, progress_callback=None):
    try:
        pt = oracle.decrypt(chosen_cipher)
        score = plausibility_score(pt)
        if progress_callback:
            progress_callback(1,1)
        return {'plaintext': pt, 'plausibility': score}
    except Exception as e:
        return {'error': str(e)}

def simulate_key_algorithm_attack(enc_bytes: bytes, alternate_algos=['AES_CBC', 'AES_ECB', 'AES_CTR'], simple_keys=None, progress_callback=None):
    if simple_keys is None:
        simple_keys = [(i).to_bytes(16, 'big') for i in range(0, 256)]
    results = []
    total = len(simple_keys) * len(alternate_algos)
    count = 0
    for algo in alternate_algos:
        for key in simple_keys:
            count += 1
            try:
                if algo == 'AES_CBC':
                    pt = local_decrypt(enc_bytes, key)
                elif algo == 'AES_ECB':
                    cipher = AES.new(key, AES.MODE_ECB)
                    data = enc_bytes
                    try:
                        suspicious = unpad(cipher.decrypt(data), AES.block_size)
                        pt = suspicious
                    except Exception:
                        continue
                elif algo == 'AES_CTR':
                    from Crypto.Util import Counter
                    ctr = Counter.new(128)
                    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                    pt = cipher.decrypt(enc_bytes)
                else:
                    continue
                score = plausibility_score(pt)
                if score > 0.75:
                    results.append({'algo': algo, 'key': key, 'score': score, 'plaintext_sample': pt[:64]})
            except Exception:
                pass
            if progress_callback:
                progress_callback(count, total)
    return results

def simulate_side_channel_timing(oracle: VulnerableOracle, enc_bytes_list, progress_callback=None):
    timings = []
    for i, c in enumerate(enc_bytes_list):
        t0 = time.time()
        try:
            oracle.decrypt(c)
        except Exception:
            pass
        t1 = time.time()
        timings.append(t1 - t0)
        if progress_callback:
            progress_callback(i+1, len(enc_bytes_list))
    mean = float(np.mean(timings))
    stdev = float(np.std(timings))
    estimated_ones = int(round((mean / 0.0005))) if oracle.timing_leak else 0
    return {'mean': mean, 'stdev': stdev, 'estimated_key_first_byte_ones': estimated_ones, 'raw_timings': timings}

class AttackSimulatorGUI:
    def __init__(self, root):
        self.root = root
        root.title("Encryption Attack Simulator - ECC+Arnold Test Harness (Simulation)")
        self.enc_bytes = None
        self.plain_bytes = None
        self.oracle = None
        self.secret_demo_key = get_random_bytes(16)
        self.attack_results = {}
        self.build_ui()

    def build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(sticky="nsew")
        file_frame = ttk.LabelFrame(frm, text="Files")
        file_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ttk.Button(file_frame, text="Load .enc file", command=self.load_enc).grid(row=0,column=0,padx=5,pady=5)
        ttk.Button(file_frame, text="Load known plaintext (optional)", command=self.load_plain).grid(row=0,column=1,padx=5,pady=5)
        ttk.Button(file_frame, text="Create sample enc from image (demo)", command=self.create_sample_enc).grid(row=0,column=2,padx=5,pady=5)
        oracle_frame = ttk.LabelFrame(frm, text="Vulnerable Oracle (simulate insecure server)")
        oracle_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.iv_var = tk.BooleanVar(value=False)
        self.timing_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(oracle_frame, text="Deterministic IV (vulnerable)", variable=self.iv_var).grid(row=0,column=0,sticky='w',padx=5,pady=2)
        ttk.Checkbutton(oracle_frame, text="Enable timing leak (simulate side-channel)", variable=self.timing_var).grid(row=0,column=1,sticky='w',padx=5,pady=2)
        ttk.Button(oracle_frame, text="(Re)create Oracle", command=self.reset_oracle).grid(row=0,column=2,padx=5,pady=2)
        ttk.Label(oracle_frame, text="(Secret key used by oracle is random demo key unless you plug in yours.)").grid(row=1,column=0,columnspan=3,sticky='w',padx=5)
        attacks_frame = ttk.LabelFrame(frm, text="Attacks")
        attacks_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        ttk.Button(attacks_frame, text="Run All Tests", command=self.run_all_tests).grid(row=0,column=0,padx=3,pady=3)
        ttk.Button(attacks_frame, text="Generate Report", command=self.generate_report).grid(row=0,column=1,padx=3,pady=3)
        self.progress = ttk.Progressbar(frm, orient='horizontal', length=600, mode='determinate')
        self.progress.grid(row=3, column=0, padx=5, pady=5)
        self.log = scrolledtext.ScrolledText(frm, width=100, height=20)
        self.log.grid(row=4, column=0, padx=5, pady=5)
        self.status = ttk.Label(frm, text="Ready.")
        self.status.grid(row=5, column=0, sticky='w', padx=5, pady=2)
        self.reset_oracle()

    def log_msg(self, *parts):
        s = " ".join(str(p) for p in parts)
        self.log.insert(tk.END, s + "\n")
        self.log.see(tk.END)

    def load_enc(self):
        path = filedialog.askopenfilename(title="Open encrypted file (.enc)", filetypes=[("Encrypted files","*.enc"),("All files","*.*")])
        if not path:
            return
        with open(path, 'rb') as f:
            self.enc_bytes = f.read()
        self.log_msg(f"Loaded encrypted file: {path} ({len(self.enc_bytes)} bytes)")
        self.status.config(text=f"Loaded: {os.path.basename(path)}")

    def load_plain(self):
        path = filedialog.askopenfilename(title="Open plaintext image file", filetypes=[("Images","*.png;*.jpg;*.jpeg;*.bmp;*.tif"),("All files","*.*")])
        if not path:
            return
        with open(path, 'rb') as f:
            self.plain_bytes = f.read()
        self.log_msg(f"Loaded known plaintext image: {path} ({len(self.plain_bytes)} bytes)")

    def create_sample_enc(self):
        img = Image.new('L', (128,128))
        arr = np.arange(128*128, dtype=np.uint8).reshape((128,128)) % 256
        img = Image.fromarray(arr)
        buf = BytesIO()
        img.save(buf, format='PNG')
        pt = buf.getvalue()
        enc = local_encrypt(pt, self.secret_demo_key)
        tmp = 'sample.enc'
        with open(tmp, 'wb') as f:
            f.write(enc)
        self.enc_bytes = enc
        self.log_msg("Created demo encrypted file sample.enc using demo internal key.")
        messagebox.showinfo("Sample created", f"Created sample.enc in current folder. Secret demo key used (hidden).")
        self.status.config(text="Created sample.enc")

    def reset_oracle(self):
        det = bool(self.iv_var.get())
        leak = bool(self.timing_var.get())
        self.oracle = VulnerableOracle(secret_key=self.secret_demo_key, deterministic_iv=det, timing_leak=leak)
        self.log_msg("Oracle (re)created. deterministic_iv=", det, "timing_leak=", leak)

    def mk_progress_cb(self, total):
        def cb(done, tot=None):
            if tot is None:
                tot = total
            frac = int((done / tot) * 100)
            self.progress['value'] = frac
            self.root.update_idletasks()
        return cb

    def run_all_tests(self):
        if not self.enc_bytes:
            messagebox.showwarning("No .enc", "Load an encrypted file first.")
            return
        self.attack_results = {}
        self.progress['value'] = 0
        self.log_msg("Starting full test suite...")
        t = threading.Thread(target=self._bg_run_all, daemon=True)
        t.start()

    def _bg_run_all(self):
        total_steps = 7
        step = 0
        def step_cb():
            nonlocal step
            step += 1
            self.progress['value'] = int((step / total_steps) * 100)
            self.root.update_idletasks()

        self.log_msg("1) Brute-force (demo small keyspace)")
        step_cb()
        bf_found = simulate_bruteforce(self.enc_bytes, 0, 1023, progress_callback=self.mk_progress_cb(1))
        if bf_found:
            self.attack_results['Brute Force'] = f"Potential Issue: {len(bf_found)} plausible key candidate(s)"
            for k, key, score in bf_found:
                self.log_msg(f"[BRUTE] candidate int={k}, key(hex)={bytes_to_hex(key)} score={score:.3f}")
        else:
            self.attack_results['Brute Force'] = "Passed (no plausible keys in tested demo space)"

        self.log_msg("2) Cipher-only analysis")
        step_cb()
        co = simulate_cipher_only_analysis(self.enc_bytes, progress_callback=self.mk_progress_cb(1))
        self.log_msg(f"[CIPHER-ONLY] length={co['length']}, entropy={co['entropy']:.3f}, blocks_total={co['blocks_total']}, ecb_suspected={co['ecb_suspected']}")
        if co['ecb_suspected']:
            self.attack_results['Cipher Only'] = "Potential Issue: ECB-like patterns suspected"
        else:
            self.attack_results['Cipher Only'] = "Passed (no ECB patterns detected)"

        self.log_msg("3) Known-plaintext test")
        step_cb()
        if self.plain_bytes:
            kp = simulate_known_plaintext(self.enc_bytes, self.plain_bytes, key_candidate=self.secret_demo_key)
            self.log_msg("[KNOWN-PLAINTEXT] Result:", kp)
            if kp.get('match'):
                self.attack_results['Known Plaintext'] = "Potential Issue: Known plaintext matched using demo key"
            else:
                self.attack_results['Known Plaintext'] = "Passed (no match with demo key)"
        else:
            self.attack_results['Known Plaintext'] = "Skipped (no known plaintext provided)"

        self.log_msg("4) Chosen-plaintext (oracle)")
        step_cb()
        cp_plain = b"TEST_CHOSEN_PLAINTEXT"
        cp = simulate_chosen_plaintext(self.oracle, cp_plain, progress_callback=self.mk_progress_cb(1))
        self.log_msg(f"[CHOSEN-PLAINTEXT] ciphertext_len={len(cp['ciphertext'])}, plausibility={cp['plausibility']:.3f}")
        if cp['plausibility'] > 0.9:
            self.attack_results['Chosen Plaintext'] = "Potential Issue: oracle returns highly plausible ciphertexts (check determinism/IV use)"
        else:
            self.attack_results['Chosen Plaintext'] = "Passed (oracle encryption appears normal for demo)"

        self.log_msg("5) Chosen-ciphertext (oracle)")
        step_cb()
        cc_cipher = self.enc_bytes
        cc = simulate_chosen_ciphertext(self.oracle, cc_cipher, progress_callback=self.mk_progress_cb(1))
        self.log_msg("[CHOSEN-CIPHERTEXT] Result:", cc)
        if cc.get('plaintext') is not None and plausibility_score(cc.get('plaintext')) > 0.8:
            self.attack_results['Chosen Ciphertext'] = "Potential Issue: oracle decrypted chosen ciphertext to plausible plaintext"
        elif cc.get('error'):
            self.attack_results['Chosen Ciphertext'] = f"Passed (oracle raised error on chosen ciphertext): {cc.get('error')}"
        else:
            self.attack_results['Chosen Ciphertext'] = "Passed (no useful plaintext from oracle)"

        self.log_msg("6) Key & algorithm sweep")
        step_cb()
        simple_keys = [(i).to_bytes(16, 'big') for i in range(0, 512)]
        ka = simulate_key_algorithm_attack(self.enc_bytes, alternate_algos=['AES_CBC','AES_ECB','AES_CTR'], simple_keys=simple_keys, progress_callback=self.mk_progress_cb(len(simple_keys)*3))
        if ka:
            self.attack_results['Key & Algorithm'] = f"Potential Issue: {len(ka)} candidate(s) produced plausible plaintext"
            for r in ka:
                self.log_msg("[KEY-ALGO] candidate:", r['algo'], bytes_to_hex(r['key']), "score", r['score'])
        else:
            self.attack_results['Key & Algorithm'] = "Passed (no plausible outputs in demo sweep)"

        self.log_msg("7) Side-channel timing simulation")
        step_cb()
        probes = []
        for _ in range(30):
            pt = b"PROBE_" + get_random_bytes(32)
            ct = self.oracle.encrypt(pt)
            probes.append(ct)
        sc = simulate_side_channel_timing(self.oracle, probes, progress_callback=self.mk_progress_cb(len(probes)))
        self.log_msg("[SIDE-CHANNEL] Mean timing: {:.6f}s, std: {:.6f}s, estimated_ones: {}".format(sc['mean'], sc['stdev'], sc['estimated_key_first_byte_ones']))
        if self.oracle.timing_leak and sc['estimated_key_first_byte_ones'] > 0:
            self.attack_results['Side Channel'] = "Potential Issue: timing leak measurable (demo)"
        else:
            self.attack_results['Side Channel'] = "Passed (no timing leak detected in demo)"

        self.progress['value'] = 100
        self.log_msg("Full test suite complete. Generating automatic report...")
        self.generate_report(auto_show=False)
        self.status.config(text="Full test suite finished")

    def generate_report(self, auto_show=True):
        report_lines = ["--- Encryption Attack Simulation Report ---", f"Date: {time.ctime()}"]
        for attack, result in self.attack_results.items():
            report_lines.append(f"{attack}: {result}")
        report_text = "\n".join(report_lines)
        self.log_msg("\n" + report_text)
        try:
            with open("attack_report.txt", "w") as f:
                f.write(report_text)
            self.log_msg("Report saved as attack_report.txt")
        except Exception as e:
            self.log_msg("Failed to save report:", e)
        if auto_show:
            messagebox.showinfo("Report Generated", "Attack report generated and saved to attack_report.txt")

def main():
    root = tk.Tk()
    app = AttackSimulatorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
