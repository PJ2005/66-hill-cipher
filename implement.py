"""
Hill Cipher — Authenticated Encryption (Encrypt-then-MAC)
==========================================================
Hash   : SpiralSponge-32 — 3-cell sponge with non-linear cross-diffusion
Cipher : Hill cipher (modular matrix multiply, nxn key)
MAC    : Encrypt-then-MAC  →  hash(ciphertext), Hill-encrypt the hash

Wire format:  ciphertext | enc-MAC   (plaintext never transmitted)
"""

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.rule    import Rule
from rich         import box
from rich.padding import Padding
from rich.prompt  import Prompt, Confirm

console = Console()

# ── Colour tokens ─────────────────────────────────────────────────────────────
CA = "bright_cyan"       # accent  – ciphertext / main values
CP = "bright_magenta"    # purple  – MAC / hash steps
CG = "bright_green"      # green   – success / recovered plaintext
CR = "bright_red"        # red     – tamper / failure
CW = "yellow"            # warn    – hash output
CD = "grey62"            # dim     – secondary info
CL = "grey78"            # label

# ── Math ──────────────────────────────────────────────────────────────────────
def mod26(x):  return ((x % 26) + 26) % 26

def mod_inv26(a):
    a = mod26(a)
    for x in range(1, 26):
        if (a * x) % 26 == 1:
            return x
    return -1

def mat_vec(A, v):
    return [mod26(sum(A[i][j]*v[j] for j in range(len(v)))) for i in range(len(A))]

def det2(M): return mod26(M[0][0]*M[1][1] - M[0][1]*M[1][0])

def det3(M):
    return mod26(
        M[0][0]*(M[1][1]*M[2][2] - M[1][2]*M[2][1])
       -M[0][1]*(M[1][0]*M[2][2] - M[1][2]*M[2][0])
       +M[0][2]*(M[1][0]*M[2][1] - M[1][1]*M[2][0]))

def mat_inv(M):
    n  = len(M)
    d  = det2(M) if n == 2 else det3(M)
    di = mod_inv26(d)
    if di == -1:
        return None
    if n == 2:
        adj = [[mod26( M[1][1]), mod26(-M[0][1])],
               [mod26(-M[1][0]), mod26( M[0][0])]]
    else:
        def minor(ri, ci):
            return [row[:ci]+row[ci+1:] for r, row in enumerate(M) if r != ri]
        adj = [[mod26((1 if (i+j)%2==0 else -1) * det2(minor(j, i)))
                for j in range(3)] for i in range(3)]
    return [[mod26(v * di) for v in row] for row in adj]

# ── SpiralSponge-32 hash ──────────────────────────────────────────────────────
#
# Design rationale:
#   Classic single-register hashes (djb2, FNV, PolyRot-32) accumulate
#   linearly into one state word.  SpiralSponge-32 maintains THREE 32-bit
#   cells (A, B, C) with cross-cell non-linear diffusion after every byte.
#
#   Absorb phase — each char feeds all three cells simultaneously:
#     each cell uses a different large prime multiplier so the same byte
#     produces three distinct contributions; a Fibonacci-stride position
#     scramble (index * 0x9E3779B9) is XORed in so anagrams diverge.
#
#   Mix phase — non-linear cross-cell diffusion:
#     A ^= rotl(B ^ C,  5)    asymmetric rotations prevent fixed points
#     B ^= rotl(C ^ A, 11)    each cell sees XOR of its two neighbours
#     C ^= rotl(A ^ B,  3)    odd rotation sizes break symmetry
#
#   Squeeze — fold A, B, C then Murmur-style multiply-xorshift avalanche.
#
#   Properties: non-linear, position-sensitive, ~50% bit-flip avalanche,
#   always returns 8 clean unsigned hex chars.

_M32 = 0xFFFFFFFF
def _rotl32(x, r): return ((x << r) | (x >> (32 - r))) & _M32

_PA, _PB, _PC = 0xCC9E2D51, 0x1B873593, 0x85EBCA6B   # absorb primes
_FIB           = 0x9E3779B9                             # Fibonacci stride

def spiral_sponge32(text: str) -> str:
    A, B, C = 0xDEADBEEF, 0xBAADF00D, 0xCAFEBABE      # distinct IVs

    for i, ch in enumerate(text):
        b   = ord(ch) & _M32
        pos = (i * _FIB) & _M32

        # Absorb: different prime per cell + position scramble
        A = (A + _rotl32((b * _PA) & _M32 ^ pos, 13)) & _M32
        B = (B + _rotl32((b * _PB) & _M32 ^ pos, 17)) & _M32
        C = (C + _rotl32((b * _PC) & _M32 ^ pos,  7)) & _M32

        # Mix: non-linear cross-cell diffusion
        A = (A ^ _rotl32((B ^ C) & _M32,  5)) & _M32
        B = (B ^ _rotl32((C ^ A) & _M32, 11)) & _M32
        C = (C ^ _rotl32((A ^ B) & _M32,  3)) & _M32

    # Squeeze: fold + Murmur avalanche
    h = (A ^ B ^ C) & _M32
    h ^= (h >> 16); h = (h * 0x85EBCA6B) & _M32
    h ^= (h >> 13); h = (h * 0xC2B2AE35) & _M32
    h ^= (h >> 16); h &= _M32

    return format(h, '08x')   # 8-char unsigned hex, no '-'

# ── Encode bridge (hex nibble <-> alpha) ──────────────────────────────────────
def hex_to_alpha(hex8: str) -> str:
    """8 hex chars -> 8 alpha chars  (0-f -> a-p)"""
    return ''.join(chr(int(c, 16) + 97) for c in hex8)

def alpha_to_hex(alpha8: str) -> str:
    """8 alpha chars -> 8 hex chars  (a-p -> 0-f)"""
    return ''.join(format(ord(c) - 97, 'x') for c in alpha8)

# ── Hill cipher ───────────────────────────────────────────────────────────────
def sanitize(s: str) -> str:
    return ''.join(c for c in s.lower() if c.isalpha())

def pad_to(s: str, n: int) -> str:
    while len(s) % n != 0:
        s += 'x'
    return s

def hill_enc(text: str, K: list) -> str:
    n, out = len(K), []
    for i in range(0, len(text), n):
        v = [ord(c) - 97 for c in text[i:i+n]]
        out.extend(chr(x + 97) for x in mat_vec(K, v))
    return ''.join(out)

def hill_dec(text: str, K: list) -> str:
    Ki = mat_inv(K)
    if Ki is None:
        raise ValueError("Key not invertible mod 26")
    n, out = len(K), []
    for i in range(0, len(text), n):
        v = [ord(c) - 97 for c in text[i:i+n]]
        out.extend(chr(x + 97) for x in mat_vec(Ki, v))
    return ''.join(out)

# ── Display helpers ───────────────────────────────────────────────────────────
def step(n, label, value, colour=CA, note=""):
    t = Table(box=None, padding=(0,1,0,0), show_header=False, expand=True)
    t.add_column("n",  width=3,  no_wrap=True)
    t.add_column("l",  width=32, no_wrap=True)
    t.add_column("v",  ratio=1)
    t.add_column("no", width=36, no_wrap=True)
    t.add_row(Text(str(n), style=f"bold {CD}"),
              Text(label,  style=CL),
              Text(value,  style=f"bold {colour}"),
              Text(note,   style=CD))
    console.print(t)

def section(title, colour):
    console.print()
    console.rule(Text(f"  {title}  ", style=f"bold {colour}"), style=colour)
    console.print()

def kstr(K):
    return "  ".join("["+",".join(str(v) for v in r)+"]" for r in K)

def show_matrix(K, label="Key matrix K"):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    for _ in K[0]: t.add_column(justify="right")
    for r in K:    t.add_row(*[str(v) for v in r])
    console.print(f"  [bold {CL}]{label}[/]")
    console.print(Padding(t, (0,0,0,4)))

# ── SENDER ────────────────────────────────────────────────────────────────────
def do_sender(message: str, K: list) -> dict:
    section("SENDER — encrypt, sign & transmit", CA)
    raw = sanitize(message)
    n   = len(K)

    step(1, "Sanitised message",        raw)

    msg_pad = pad_to(raw, n)
    cipher  = hill_enc(msg_pad, K)
    step(2, "Pad message to block",     msg_pad, CD, f"length {len(msg_pad)}, multiple of {n}")
    step(3, "Hill encrypt message",     cipher,  CA, f"K = {kstr(K)}")

    hx      = spiral_sponge32(cipher)
    step(4, "SpiralSponge-32(cipher)",  hx,      CW, "hashes ciphertext, not plaintext")

    ha      = hex_to_alpha(hx)
    ha_pad  = pad_to(ha, n)
    mac     = hill_enc(ha_pad, K)
    step(5, "Hash hex -> alpha",        ha,      CP, "nibble 0-f -> char a-p")
    step(6, "Pad hash alpha",           ha_pad,  CD, f"length {len(ha_pad)}, multiple of {n}")
    step(7, "Hill encrypt MAC",         mac,     CP, f"K = {kstr(K)}")

    payload = f"{cipher} | {mac}"
    step(8, "Transmitted payload",      payload, CG, "ciphertext || enc-MAC  (no plaintext!)")

    console.print()
    console.print(Panel(
        f"[{CA}]{cipher}[/]  [{CD}]|[/]  [{CP}]{mac}[/]",
        title="[bold]Payload on the wire[/]",
        subtitle="[grey50]ciphertext  |  encrypted MAC[/]",
        border_style=CG, padding=(0,2)
    ))

    return dict(raw=raw, cipher=cipher, hx=hx, ha=ha, ha_pad=ha_pad,
                mac=mac, hlen=len(ha), K=K, n=n)

# ── RECEIVER ──────────────────────────────────────────────────────────────────
def do_receiver(ctx: dict, tampered_cipher: str = None):
    section("RECEIVER — verify MAC, then decrypt", CP)

    K    = ctx["K"]
    recv = tampered_cipher if tampered_cipher else ctx["cipher"]
    mac  = ctx["mac"]
    is_t = tampered_cipher is not None

    step(1, "Received ciphertext",
         recv + (" <- TAMPERED" if is_t else ""),
         CR if is_t else CA)
    step(2, "Received enc-MAC", mac, CP)

    dec_pad = hill_dec(mac, K)
    dec_ha  = dec_pad[:ctx["hlen"]]
    dec_hx  = alpha_to_hex(dec_ha)
    recomp  = spiral_sponge32(recv)

    step(3, "Hill decrypt enc-MAC",          dec_pad, CD, "K^-1 mod 26")
    step(4, f"Slice first {ctx['hlen']} chars", dec_ha, CP, "strips block-align padding")
    step(5, "Alpha -> hex (recovered hash)", dec_hx,  CG if dec_hx == recomp else CR)
    step(6, "SpiralSponge-32(received)",     recomp,  CG if dec_hx == recomp else CD)

    match = dec_hx == recomp
    console.print()

    if not match:
        console.print(Panel(
            Text(
                f"x  MAC MISMATCH — decryption aborted\n"
                f"   recovered : {dec_hx}\n"
                f"   recomputed: {recomp}",
                style=CR
            ),
            title="[bold red]AUTHENTICATION FAILED[/]",
            border_style=CR, padding=(0,2)
        ))
        return None

    console.print(Panel(
        Text("v  MAC verified — proceeding to decrypt", style=CG),
        title="[bold green]AUTHENTICATION PASSED[/]",
        border_style=CG, padding=(0,2)
    ))
    console.print()

    dec_raw = hill_dec(recv, K)
    step(7, "Hill decrypt ciphertext",   dec_raw,            CD, "K^-1 mod 26")
    plain   = dec_raw.rstrip('x')
    step(8, "Strip padding -> plaintext", plain,             CG)

    console.print()
    console.print(Panel(
        f"[bold {CG}]{plain}[/]",
        title="[bold]Recovered plaintext[/]",
        border_style=CG, padding=(0,2)
    ))
    return plain

# ── SUMMARY ───────────────────────────────────────────────────────────────────
def show_summary(ctx: dict, recovered):
    section("SUMMARY", "white")
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold white",
              border_style="grey37", padding=(0,2))
    t.add_column("Stage",  style=CL, width=24)
    t.add_column("Value",  style=CA, ratio=1)
    t.add_column("Note",   style=CD, width=36)

    t.add_row("Original message",    ctx["raw"],    "plaintext — never transmitted")
    t.add_row("Ciphertext",          ctx["cipher"], "what travels on the wire")
    t.add_row("Hash (hex)",          ctx["hx"],     "SpiralSponge-32 of ciphertext")
    t.add_row("Hash (alpha)",        ctx["ha"],     "bridge encoding for Hill cipher")
    t.add_row("enc-MAC",             ctx["mac"],    "Hill encrypt of hash alpha")
    result = (f"[bold {CG}]{recovered}[/]" if recovered
              else f"[bold {CR}]REJECTED — tamper detected[/]")
    t.add_row("Recovered plaintext", result,        "after MAC check + decrypt")
    console.print(t)

# ── INPUT HELPERS ─────────────────────────────────────────────────────────────
def ask_message() -> str:
    console.print()
    while True:
        raw   = Prompt.ask(f"  [{CA}]Enter plaintext message[/] [{CD}](a-z, spaces ignored)[/]")
        clean = sanitize(raw)
        if clean:
            return clean
        console.print(f"  [{CR}]No alphabetic characters found — try again.[/]")

def ask_key() -> list:
    console.print()
    console.print(f"  [{CL}]Choose key matrix size:[/]")
    console.print(f"  [{CD}]  1)  2x2  (default) — det=9,  gcd(9,26)=1[/]")
    console.print(f"  [{CD}]  2)  3x3             — det=25, gcd(25,26)=1[/]")
    choice = Prompt.ask(f"  [{CA}]Select[/]", choices=["1", "2"], default="1")
    return [[3,3],[2,5]] if choice == "1" else [[6,24,1],[13,16,10],[20,17,15]]

def ask_tamper(cipher: str):
    console.print()
    do_it = Confirm.ask(
        f"  [{CR}]Simulate a man-in-the-middle tampering attack?[/]",
        default=False
    )
    if not do_it:
        return None

    console.print(f"\n  [{CL}]Ciphertext on the wire :[/] [{CA}]{cipher}[/]")
    console.print(f"  [{CD}]Enter a modified version (same length, a-z only).[/]")
    console.print(f"  [{CD}]The attacker sees the ciphertext but not the key.[/]\n")

    while True:
        raw = Prompt.ask(f"  [{CR}]Tampered ciphertext[/]")
        t   = sanitize(raw)
        if not t:
            console.print(f"  [{CR}]Must contain alphabetic characters.[/]")
        elif len(t) != len(cipher):
            console.print(f"  [{CR}]Length must match ciphertext ({len(cipher)} chars) — got {len(t)}.[/]")
        elif t == cipher:
            console.print(f"  [{CR}]Identical to original — change at least one character.[/]")
        else:
            return t

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Hill Cipher — Authenticated Encryption\n", "bold white"),
            ("SpiralSponge-32  .  Encrypt-then-MAC  .  Modular matrix inverse", CD)
        ),
        border_style="grey37", padding=(0,2)
    ))

    message  = ask_message()
    K        = ask_key()

    console.print()
    console.print(Rule("[bold white] Configuration [/]", style="grey37"))
    show_matrix(K)
    console.print(f"  [{CL}]Message :[/] [{CA}]{message}[/]")

    ctx      = do_sender(message, K)
    tampered = ask_tamper(ctx["cipher"])

    if tampered:
        console.print()
        console.print(Panel(
            f"[{CL}]Original :[/] [{CA}]{ctx['cipher']}[/]\n"
            f"[{CL}]Tampered :[/] [{CR}]{tampered}[/]",
            title="[bold red]Man-in-the-Middle Attack[/]",
            border_style=CR, padding=(0,1)
        ))

    recovered = do_receiver(ctx, tampered_cipher=tampered)
    show_summary(ctx, recovered)
    console.print()

if __name__ == "__main__":
    main()