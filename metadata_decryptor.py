import sys, struct, argparse, time
import numpy as np

def elf_rodata(f):
    f.seek(0); h = f.read(64)
    if h[:4] != b"\x7fELF" or h[4] != 2:
        raise SystemExit("это не 64-битный ELF")
    shoff, = struct.unpack_from("<Q", h, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", h, 0x3A)
    f.seek(shoff); sh = f.read(shentsize * shnum)
    secs = []
    for i in range(shnum):
        n, t, fl, addr, off, size = struct.unpack_from("<IIQQQQ", sh, i * shentsize)
        secs.append((n, t, off, size))
    _, _, stroff, strsize = secs[shstrndx]
    f.seek(stroff); names = f.read(strsize)
    for n, t, off, size in secs:
        nm = names[n:names.index(b"\0", n)]
        if nm == b".rodata":
            return off, size
    raise SystemExit(".rodata не найден")

W = 95
def find_pile_windows(words):
    ai = words.astype(np.int64)
    def roll(x):
        c = np.concatenate([[0], np.cumsum(x, dtype=np.int64)])
        return c[W:] - c[:-W]
    sg = roll(((ai >= 256) & (ai < 0x4000000)))
    sz = roll(ai == 0)
    sb = roll(ai >= 0x10000)
    s256 = roll((ai & 0xff) == 0)
    mask = (sg + sz >= 90) & (sz <= 8) & (sb >= 25) & (sb <= 60) & ((s256 - sz) <= 22)
    cand = np.nonzero(mask)[0]
    cand = cand[cand % 4 == 0]
    best = []
    for p in cand:
        if chain_score(ai[p:p + W]) >= 15:
            best.append(int(p))
    return best

def chain_score(w):
    S = np.unique(w[w >= 0x10000]); Sall = np.unique(w[w >= 0x100])
    if len(S) < 20: return 0
    found = set(); x = S[:, None]
    for pad in range(8):
        z = x + Sall[None, :] + pad
        xi, yi = np.nonzero(np.isin(z, S))
        for i, j in zip(xi, yi):
            found.add(int(S[i]) + int(Sall[j]) + pad)
    return len(found)

MEMORDER = [
 ("exported",4),("refAsm",4),("fields",12),("fieldRefs",8),("images",36),("defData",1),("params",12),
 ("litData",1),("vtable",4),("methods",32),("interfaces",4),("attrRange",8),("marshal",12),
 ("assemblies",68),("genParams",14),("fieldDef",12),("genContainers",16),("nested",4),("constraints",4),
 ("paramDef",12),("props",20),("events",24),("attrData",1),("unresRanges",8),("typedefs",82),
 ("ifaceOff",8),("unresTypes",4),("litStarts",4),("strings",1)]

def solve_layout(P, limit=1 << 40, raw=None, c0=0):
    Pset = set(int(x) for x in P)
    srt = sorted(Pset)
    sol = {}
    def options(i, off, used):
        name, st = MEMORDER[i]
        res = {}
        def add(rank, c, n):
            if (c, n) not in res or res[(c, n)] > rank: res[(c, n)] = rank
        for c in srt:
            if c < 1: continue
            if not (c in used and st != 1):
                size = c * st
                for pad in range(8):
                    n = off + size + pad
                    if n in Pset and n > off:
                        add(0 if size in Pset else 1, c, n)
            if c % st == 0 and c // st >= 1 and st != 1:
                size = c
                for pad in range(8):
                    n = off + size + pad
                    if n in Pset and n > off:
                        add(2, c // st, n)
        for n in srt:
            if n <= off: continue
            gap = n - off
            for pad in range(8):
                if gap - pad > 0 and (gap - pad) % st == 0:
                    add(3, (gap - pad) // st, n); break
        return [k for k, _ in sorted(res.items(), key=lambda kv: (kv[1], kv[0][1]))]
    budget = [60000]
    def dfs(i, off, used):
        budget[0] -= 1
        if budget[0] < 0: raise TimeoutError
        name, st = MEMORDER[i]
        if i == len(MEMORDER) - 1:
            excl = set()
            for k, (o, c) in sol.items():
                excl |= {o, c, c * dict(MEMORDER)[k]}
            rest = [c for c in srt if c >= 100000 and c not in excl and c not in used and off + c <= limit
                    and (raw is None or raw[c0 + off + c - 1] == 0)]
            if not rest: return False
            sol[name] = (off, max(rest)); return True
        for c, nxt in options(i, off, used):
            sol[name] = (off, c)
            if dfs(i + 1, nxt, used | {c}): return True
        sol.pop(name, None)
        return False
    if 0x17c not in Pset: return None
    try:
        return dict(sol) if dfs(0, 0x17c, frozenset()) else None
    except TimeoutError:
        return None

U32, I32, U16, I16 = '<u4', '<i4', '<u2', '<i2'

class Conv:
    def __init__(self, raw, c, SEC):
        self.raw, self.c, self.SEC = raw, c, SEC
        self.M = memoryview(raw)
    def seg(self, off, size):
        return bytes(self.M[self.c + off:self.c + off + size])
    def arr(self, name):
        off, n = self.SEC[name]; st = dict(MEMORDER)[name]
        f = self.c + off
        return np.frombuffer(bytes(self.M[f:f + st * n]), dtype=np.uint8).reshape(n, st)

def fld(r, o, w, signed=False):
    v = np.zeros(r.shape[0], dtype=np.int64)
    for k in range(w): v |= r[:, o + k].astype(np.int64) << (8 * k)
    if signed:
        sign = 1 << (8 * w - 1); v = (v ^ sign) - sign
    return v

def pack(cols, dtypes):
    dt = np.dtype([(f"f{i}", d) for i, d in enumerate(dtypes)])
    out = np.zeros(len(cols[0]), dtype=dt)
    for i, col in enumerate(cols):
        d = np.dtype(dtypes[i])
        v = col.astype(np.int64)
        out[f"f{i}"] = v.astype(d) if d.kind == 'i' else (v & ((1 << (8 * d.itemsize)) - 1)).astype(d)
    return out.tobytes()

def convert(cv):
    SEC = cv.SEC; out = {}
    for k, st in MEMORDER:
        if k in ("exported","refAsm","vtable","nested","interfaces","constraints","unresTypes","unresRanges",
                 "attrRange","ifaceOff"):
            off, n = SEC[k]; out[k] = cv.seg(off, st * n)
        elif k in ("defData","litData","attrData","strings"):
            off, n = SEC[k]; out[k] = cv.seg(off, n)
    R = cv.arr
    r = R("fields");  out["fields"] = pack([fld(r,0,4),fld(r,8,4),fld(r,4,4)], [U32,U32,U32])
    r = R("params");  out["params"] = pack([fld(r,4,4),fld(r,0,4),fld(r,8,4)], [U32,U32,U32])
    r = R("props");   out["props"] = pack([fld(r,8,4),fld(r,4,4),fld(r,16,4),fld(r,0,4),fld(r,12,4)], [U32,I32,I32,U32,U32])
    r = R("events");  out["events"] = pack([fld(r,20,4),fld(r,12,4),fld(r,4,4),fld(r,0,4),fld(r,8,4),fld(r,16,4)], [U32,I32,I32,I32,I32,U32])
    r = R("genContainers"); out["genContainers"] = pack([fld(r,12,4),fld(r,0,4),fld(r,8,4),fld(r,4,4)], [I32,I32,I32,I32])
    r = R("genParams"); out["genParams"] = pack([fld(r,2,2),fld(r,4,4),fld(r,10,2),fld(r,0,2),fld(r,8,2),fld(r,12,2)], [I32,I32,I16,I16,U16,U16])
    r = R("fieldDef"); out["fieldDef"] = pack([fld(r,4,4),fld(r,8,4),fld(r,0,4)], [I32,I32,I32])
    r = R("paramDef"); out["paramDef"] = pack([fld(r,0,4),fld(r,8,4),fld(r,4,4)], [I32,I32,I32])
    r = R("marshal");  out["marshal"] = pack([fld(r,0,4),fld(r,8,4),fld(r,4,4)], [I32,I32,I32])
    r = R("fieldRefs"); out["fieldRefs"] = pack([fld(r,4,4),fld(r,0,4)], [I32,I32])
    off, n = SEC["litStarts"]
    starts = np.frombuffer(cv.seg(off, 4 * n), dtype='<u4').astype(np.int64)
    out["literals"] = pack([np.diff(starts), starts[:-1]], [U32, I32])
    r = R("methods"); NM = r.shape[0]
    mgc = fld(r,6,2); mgc = np.where(mgc == 0xffff, -1, mgc)
    out["methods"] = pack([fld(r,14,4),fld(r,26,2),fld(r,18,4),fld(r,22,4),fld(r,0,4),mgc,fld(r,10,4),
                           fld(r,30,2),fld(r,4,2),fld(r,8,2),fld(r,28,2)],
                          [U32,I32,I32,U32,I32,I32,U32,U16,U16,U16,U16])
    r = R("images"); NI = r.shape[0]
    exps = fld(r,22,2); exps = np.where(exps == 0xffff, -1, exps)
    out["images"] = pack([fld(r,24,4),fld(r,32,4),fld(r,8,2),fld(r,14,2),exps,fld(r,28,4),fld(r,4,4),
                          np.full(NI,1),fld(r,10,4),fld(r,0,4)],
                         [U32,I32,I32,U32,I32,I32,I32,U32,I32,U32])
    r = R("assemblies"); NA = r.shape[0]
    pk = r[:, 40:48].copy()
    cols = [fld(r,56,4),fld(r,60,4),fld(r,48,4),fld(r,64,4),fld(r,0,4),fld(r,28,4),fld(r,12,4),fld(r,8,4),
            np.zeros(NA,dtype=np.int64),fld(r,4,4),fld(r,24,4),fld(r,16,4),fld(r,20,4),fld(r,32,4)]
    dt = [I32,U32,I32,I32,U32,I32,I32,U32,I32,U32,I32,I32,I32,I32]
    asm = np.zeros(NA, dtype=np.dtype([(f"f{i}",d) for i,d in enumerate(dt)] + [("tok","u1",(8,))]))
    for i, col in enumerate(cols):
        d = np.dtype(dt[i]); v = col.astype(np.int64)
        asm[f"f{i}"] = (v if d.kind == 'i' else v & 0xffffffff).astype(d)
    asm["tok"] = pk
    out["assemblies"] = asm.tobytes()
    r = R("typedefs"); NT = r.shape[0]
    flags = fld(r,78,4); bit = fld(r,38,4); fieldStart = fld(r,24,4,True)
    ftype = fld(R("fields"),8,4)
    elem = np.full(NT, -1, dtype=np.int64)
    idx = np.nonzero(((bit & 2) != 0) & (fieldStart >= 0))[0]
    elem[idx] = ftype[fieldStart[idx]]
    em = (bit & 2) != 0
    sb = out["strings"]
    tn = fld(r,52,4); tns = fld(r,60,4)
    enum_td = [i for i in np.nonzero(em == False)[0] if sb[tn[i]:tn[i]+5] == b"Enum\0" and sb[tns[i]:tns[i]+7] == b"System\0"]
    parent = fld(r,0,4,True).copy()
    if enum_td:
        elem[em] = parent[em]
        parent[em] = fld(r,12,4,True)[enum_td[0]]
    gcont = fld(r,64,2); gcont = np.where(gcont == 0xffff, -1, gcont)
    s = lambda o, w=4: fld(r, o, w, True)
    cols = [fld(r,52,4), fld(r,60,4,True), fld(r,12,4,True), s(28), parent, elem, gcont, flags,
            s(24), s(72), s(8), s(4), s(68), s(16), s(32), s(48),
            fld(r,44,2),fld(r,56,2),fld(r,36,2),fld(r,76,2),fld(r,58,2),fld(r,42,2),fld(r,66,2),fld(r,46,2),
            bit, fld(r,20,4)]
    dts = [U32,U32,I32,I32,I32,I32,I32,U32, I32,I32,I32,I32,I32,I32,I32,I32,
           U16,U16,U16,U16,U16,U16,U16,U16, U32,U32]
    out["typedefs"] = pack(cols, dts)
    return out

STD_ORDER = ["literals","litData","strings","events","props","methods","paramDef","fieldDef","defData","marshal",
             "params","fields","genParams","constraints","genContainers","nested","interfaces","vtable","ifaceOff",
             "typedefs","images","assemblies","fieldRefs","refAsm","attrData","attrRange","unresTypes","unresRanges",
             None, None, "exported"]

def build_dat(out):
    hdr = bytearray(256); struct.pack_into("<II", hdr, 0, 0xFAB11BAF, 31)
    body = bytearray(); pos = 256
    for i, k in enumerate(STD_ORDER):
        if k is None:
            struct.pack_into("<II", hdr, 8 + 8 * i, pos, 0); continue
        data = out[k]
        struct.pack_into("<II", hdr, 8 + 8 * i, pos, len(data))
        body += data; pos += len(data)
        pad = (-pos) % 4; body += b"\0" * pad; pos += pad
    return bytes(hdr) + bytes(body)

def ident_ok(b):
    return len(b) >= 3 and all(ch in b"_.<>`$/+-,=[]()|:" or 48 <= ch <= 57 or 65 <= ch <= 90 or 97 <= ch <= 122 for ch in b)

def strings_anchor(raw, c, SEC):
    off, n = SEC["strings"]; p = c + off
    if raw[p - 1] != 0: return False
    e = raw.find(b"\0", p, p + 200)
    return e > p and ident_ok(raw[p:e]) and b"<Module>\0" in raw[p:p + 400]

def selfcheck(cv, out):
    S = cv.SEC; rep = []
    def ok(c, msg): rep.append(("OK  " if c else "FAIL") + " " + msg); return c
    nt = S["typedefs"][1]; ni = S["images"][1]
    good = True
    good &= ok(strings_anchor(cv.raw, cv.c, S), "таблица строк начинается с имени сборки и содержит <Module>")
    nested = np.frombuffer(out["nested"], dtype='<u4'); good &= ok(nested.max() < nt, f"nested: max {nested.max()} < typedefs {nt}")
    td = np.frombuffer(out["typedefs"], dtype=np.dtype([("f%d" % i, d) for i, d in enumerate(
        [U32,U32,I32,I32,I32,I32,I32,U32,I32,I32,I32,I32,I32,I32,I32,I32,U16,U16,U16,U16,U16,U16,U16,U16,U32,U32])]))
    sl = np.frombuffer(out["strings"], dtype=np.uint8)
    nm = td["f0"]; good &= ok(int(nm.max()) < len(sl), "typedef.nameIndex в пределах таблицы строк")
    nmi = np.minimum(nm.astype(np.int64), len(sl)) - 1
    good &= ok(int((sl[nmi] == 0).sum()) >= nt * 0.99, "typedef.nameIndex попадает на начало строки (>=99%)")
    ms = np.frombuffer(out["methods"], dtype=np.dtype([("f%d" % i, d) for i, d in enumerate([U32,I32,I32,U32,I32,I32,U32,U16,U16,U16,U16])]))
    good &= ok(int(ms["f0"].max()) < len(sl), "method.nameIndex в пределах таблицы строк")
    good &= ok(int((sl[np.minimum(ms["f0"].astype(np.int64), len(sl)) - 1] == 0).sum()) >= len(ms) * 0.99, "method.nameIndex на начале строки (>=99%)")
    good &= ok(int(ms["f1"].max()) < nt, "method.declaringType < typedefs")
    return good, rep

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lib"); ap.add_argument("-o", "--out", default="global-metadata.dat")
    a = ap.parse_args(); t0 = time.time()
    with open(a.lib, "rb") as f:
        ro_off, ro_size = elf_rodata(f)
        f.seek(ro_off); raw = f.read(ro_size)
    print(f"[+] .rodata: off=0x{ro_off:x} size=0x{ro_size:x}")
    n4 = len(raw) // 4
    words = np.frombuffer(raw[:n4 * 4], dtype='<u4')
    print("[*] ищу кучу заголовка (содержимое, без сигнатур)...")
    wins = find_pile_windows(words)
    if not wins:
        raise SystemExit("[-] куча не найдена: формат защиты изменился (нужен ручной разбор)")
    lo, hi = min(wins) - 8, max(wins) + 8
    print(f"[+] кандидатное окно: .rodata+0x{lo*4:x} .. +0x{hi*4:x}  ({time.time()-t0:.0f}s)")
    result = None
    for p in range(max(lo, 0), hi + 1):
        P = words[p:p + W]
        SEC = solve_layout(P, len(raw) - p * 4, raw, p * 4)
        if not SEC: continue
        c = p * 4
        if not strings_anchor(raw, c, SEC): continue
        result = (c, SEC); break
    if not result:
        raise SystemExit("[-] не удалось восстановить цепочку секций (изменился порядок/размеры структур)")
    c, SEC = result
    print(f"[+] заголовок метадаты (B0) = файл 0x{ro_off + c:x}")
    for k, _ in MEMORDER: print(f"    {k:14s} off=0x{SEC[k][0]:08x} count={SEC[k][1]}")
    cv = Conv(raw, c, SEC); out = convert(cv)
    good, rep = selfcheck(cv, out)
    print("\n".join(rep))
    dat = build_dat(out)
    with open(a.out, "wb") as f: f.write(dat)
    print(f"[+] записано {a.out}: {len(dat)} байт, typedefs={SEC['typedefs'][1]}, images={SEC['images'][1]}")
    if not good: print("[!] часть проверок не прошла — результат ненадёжен")

if __name__ == "__main__":
    main()
