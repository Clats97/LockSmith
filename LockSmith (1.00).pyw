from __future__ import annotations
import hashlib
import hmac
import importlib
import os
import queue
import secrets
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import font, ttk
from typing import Union
try:
    import psutil                              
except ImportError:                            
    psutil = None                              
def _require_blake3():
    try:
        return importlib.import_module("blake3")
    except ModuleNotFoundError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", "blake3"]
            )
            return importlib.import_module("blake3")
        except Exception as exc:
            raise ImportError(
                "Unable to import the 'blake3' module.\n"
                "Install it manually with:  pip install blake3"
            ) from exc

blake3 = _require_blake3()
POOL_SIZE = 3 * 64                             
pool      = bytearray(POOL_SIZE)
pos       = 0
mixCount  = 0
frozen    = False
_pool_lock        = threading.RLock()
_new_entropy_lock = threading.Lock()
_new_entropy      = hashlib.sha512()
_ui_queue: "queue.Queue[dict[str, Union[str, int]]]" = queue.Queue(maxsize=8)
_ASCII = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "1234567890"
    "~`!@#$%^&*()-_=+{[}]|\\:;\"'<,>.?/"
)
_ALPHANUM = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "1234567890"
)
_HEX = "0123456789ABCDEF"

def _uniform_index(n: int) -> int:
    return secrets.randbelow(n)

def _expand_key(key: bytes, length: int = 64, *, use_sha3: bool = True) -> bytes:
    digest = hashlib.sha3_512 if use_sha3 else hashlib.sha512
    prk = hmac.new(b"WinPassGen-HKDF-extract", key, digest).digest()
    out, counter, tmp = b"", 1, b""
    while len(out) < length:
        tmp = hmac.new(
            prk, tmp + b"\x01" + counter.to_bytes(1, "big"), digest
        ).digest()
        out += tmp
        counter += 1
    return out[:length]

def _mix() -> None:
    global mixCount
    with _pool_lock:
        digest = blake3.blake3(pool).digest()  
        for i in range(POOL_SIZE):
            pool[i] ^= digest[i % 32]
        mixCount += 1

def _mixin(data: bytes) -> None:
    global pos
    if not data:
        return
    with _pool_lock:
        for b in data:
            pool[pos] = (pool[pos] + b) & 0xFF
            pos = (pos + 1) % POOL_SIZE
            if pos == 0:
                _mix()
    _mix()

def _pool_to_pass(
    charset: str, *, enforce_complex: bool = False, length: int = 64
) -> str:
    _mixin(secrets.token_bytes(32))
    _mixin(int(time.perf_counter_ns()).to_bytes(8, "little"))

    with _pool_lock:
        snapshot = bytes(pool[:32])
    _mix()
    stream = _expand_key(snapshot, length * 2)
    idx = 0
    out: list[str] = []
    if enforce_complex:
        cat_tbl = {
            "lower": set("abcdefghijklmnopqrstuvwxyz"),
            "upper": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "digit": set("0123456789"),
            "sym":   set("~`!@#$%^&*()-_=+{[}]|\\:;\"'<,>.?/"),
        }
    while len(out) < length:
        if idx >= len(stream):
            stream = _expand_key(snapshot + bytes(out, "ascii"), length * 2)
            idx = 0
        byte_val = stream[idx]
        idx += 1
        if byte_val >= 256 - (256 % len(charset)):
            continue
        out.append(charset[byte_val % len(charset)])
    if enforce_complex:
        missing = {
            cat for cat, chars in cat_tbl.items() if not any(c in chars for c in out)
        }
        for cat in missing:
            out[_uniform_index(length)] = secrets.choice(tuple(cat_tbl[cat]))

    _mixin(snapshot)
    return "".join(out)

def _add_mouse_entropy(event: tk.Event) -> None:  # type: ignore
    with _new_entropy_lock:
        _new_entropy.update(
            struct.pack(
                "<QQQQ",
                time.perf_counter_ns(),
                event.x & 0xFFFFFFFF,
                event.y & 0xFFFFFFFF,
                getattr(event, "type_num", hash(event.type)) & 0xFFFFFFFF,
            )
        )
    x_val_var.set(str(event.x))
    y_val_var.set(str(event.y))
    timer_var.set(str(time.perf_counter_ns()))

def _mixer(stop_evt: threading.Event) -> None:
    global _new_entropy
    proc = psutil.Process(os.getpid()) if psutil else None

    while not stop_evt.is_set():
        with _new_entropy_lock:
            digest = _new_entropy.digest()
            _new_entropy = hashlib.sha512()
        _mixin(digest)

        _mixin(secrets.token_bytes(32))
        _mixin(int(time.perf_counter_ns()).to_bytes(8, "little"))
        if proc:
            _mixin(int(proc.memory_info().rss).to_bytes(8, "little"))

        if mixCount & 0xFF == 0:
            _mixin(os.urandom(32))

        if not frozen:
            try:
                _ui_queue.put_nowait(
                    {
                        "ascii": _pool_to_pass(_ASCII, enforce_complex=True),
                        "alphanum": _pool_to_pass(
                            _ALPHANUM, enforce_complex=False
                        ),
                        "hex": _pool_to_pass(_HEX, enforce_complex=False),
                        "mix": mixCount,
                    }
                )
            except queue.Full:
                pass

        time.sleep(0.02)

root = tk.Tk()
root.title("LockSmith Password Generator v1.00")
mono = font.Font(family="Courier New", size=10)
ascii_banner_font = font.Font(family="Courier New", size=10, weight="bold")
subtitle_font = font.Font(family="Courier New", size=10)
header_frame = ttk.Frame(root, padding=(4, 4, 4, 2))
header_frame.pack(fill=tk.X)
ascii_banner = (
    "██╗      ██████╗  ██████╗██╗  ██╗███████╗███╗   ███╗██╗████████╗██╗  ██╗\n"
    "██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝████╗ ████║██║╚══██╔══╝██║  ██║\n"
    "██║     ██║   ██║██║     █████╔╝ ███████╗██╔████╔██║██║   ██║   ███████║\n"
    "██║     ██║   ██║██║     ██╔═██╗ ╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║\n"
    "███████╗╚██████╔╝╚██████╗██║  ██╗███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║\n"
    "╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
)
ttk.Label(
    header_frame,
    text=ascii_banner,
    foreground="#ff0000",
    font=ascii_banner_font,
    justify=tk.LEFT,
).pack(anchor=tk.W)
sub_frame = ttk.Frame(header_frame)
sub_frame.pack(fill=tk.X, pady=(2, 0))
ttk.Label(
    sub_frame,
    text="S E C U R E   P A S S W O R D   G E N E R A T O R",
    foreground="#0000ff",
    font=subtitle_font,
).pack(side=tk.LEFT, anchor=tk.W)
ttk.Label(
    sub_frame,
    text="Version 1.00",
    foreground="#ff0000",
    font=subtitle_font,
).pack(side=tk.LEFT, padx=(8, 0))
ttk.Label(
    header_frame,
    text="By Joshua M Clatney - Ethical Pentesting Enthusiast",
    font=subtitle_font,
).pack(anchor=tk.W, pady=(0, 4))
body = ttk.Frame(root, padding=8)
body.pack(fill=tk.BOTH, expand=True)
ascii_var = tk.StringVar(root, "—" * 64)
alphanum_var = tk.StringVar(root, "—" * 64)
hex_var = tk.StringVar(root, "—" * 64)
x_val_var = tk.StringVar(root, "0")
y_val_var = tk.StringVar(root, "0")
timer_var = tk.StringVar(root, "0")
mix_var = tk.StringVar(root, "0")

def _row(label: str, var: tk.StringVar) -> None:
    frame = ttk.Frame(body)
    ttk.Label(frame, text=label).pack(side=tk.LEFT, padx=(0, 4))
    ttk.Entry(frame, textvariable=var, font=mono, width=66).pack(
        side=tk.LEFT, fill=tk.X, expand=True
    )
    frame.pack(fill=tk.X, pady=2)

for lbl, var in (
    ("ASCII:", ascii_var),
    ("Alphanumeric:", alphanum_var),
    ("Hex:", hex_var),
):
    _row(lbl, var)
pad_frame = ttk.Frame(body, padding=(0, 10, 0, 0))
pad_frame.pack(fill=tk.X)
ttk.Label(pad_frame, text="Move mouse in the box below to add entropy:").pack(
    anchor=tk.W
)
entropy_pad = tk.Canvas(
    pad_frame,
    width=300,
    height=100,
    bg="#eeeeee",
    highlightthickness=1,
    highlightbackground="black",
)
entropy_pad.pack(pady=4)
entropy_pad.bind("<Motion>", _add_mouse_entropy)
status = ttk.Frame(body)
status.pack(fill=tk.X, pady=(8, 2))
for lbl, var, width in (
    ("X:", x_val_var, 6),
    ("Y:", y_val_var, 6),
    ("Timer:", timer_var, 18),
    ("Mixes:", mix_var, 8),
):
    ttk.Label(status, text=lbl).pack(side=tk.LEFT)
    ttk.Label(status, textvariable=var, width=width).pack(
        side=tk.LEFT, padx=(0, 8)
    )

def _toggle() -> None:
    global frozen
    frozen = not frozen
    freeze_btn.config(text="Unfreeze" if frozen else "Freeze")

freeze_btn = ttk.Button(body, text="Freeze", command=_toggle)
freeze_btn.pack(pady=(6, 0))
def _drain_queue() -> None:
    try:
        while True:
            data = _ui_queue.get_nowait()
            ascii_var.set(data["ascii"])
            alphanum_var.set(data["alphanum"])
            hex_var.set(data["hex"])
            mix_var.set(str(data["mix"]))
    except queue.Empty:
        pass
    root.after(15, _drain_queue)

stop_evt = threading.Event()
threading.Thread(target=_mixer, args=(stop_evt,), daemon=True).start()

root.after(15, _drain_queue)
try:
    root.mainloop()
finally:
    stop_evt.set()