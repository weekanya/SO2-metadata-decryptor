import sys, struct, mmap, shutil, os

def die(m): print("[-] " + m); sys.exit(1)

def main():
    if len(sys.argv) < 4: die("usage: libunity_patch.py libunity.so global-metadata.dat out.so")
    lib, metaf, outf = sys.argv[1:4]
    dat = open(metaf, "rb").read()
    hdr = struct.unpack_from("<64I", dat, 0)
    if hdr[0] != 0xFAB11BAF: die("global-metadata.dat: неверная сигнатура")
    def ssize(i): return hdr[3 + 2 * i]
    NT = ssize(19) // 88; NI = ssize(20) // 40; NU = ssize(27) // 8
    print("[*] метадата: typedefs=%d images=%d unresolvedRanges=%d" % (NT, NI, NU))

    f = open(lib, "rb"); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    phoff, = struct.unpack_from("<Q", m, 0x20); pe, pn = struct.unpack_from("<HH", m, 0x36)
    phdrs = []; loads = []; dynp = None
    for i in range(pn):
        t, fl, off, va, pa, fs, ms, al = struct.unpack_from("<IIQQQQQQ", m, phoff + i * pe)
        phdrs.append((i, t, fl, off, va, fs, ms))
        if t == 1: loads.append((off, va, fs, ms, fl))
        if t == 2: dynp = (off, va, fs)
    def fo(v):
        for off, va, fs, ms, fl in loads:
            if va <= v < va + fs: return off + v - va
        return None
    doff = fo(dynp[1]); tags = {}; didx = {}
    for i in range(0, dynp[2], 16):
        t, v = struct.unpack_from("<QQ", m, doff + i)
        if t == 0: break
        tags.setdefault(t, v); didx.setdefault(t, i)
    ra, rs = tags.get(7), tags.get(8)
    segs = [[va, fs, bytearray(m[off:off + fs]), off] for off, va, fs, ms, fl in loads if fl & 2]
    if ra:
        ro = fo(ra); n = 0
        for i in range(ro, ro + rs, 24):
            off, info, add = struct.unpack_from("<QQq", m, i)
            if (info & 0xffffffff) != 1027: continue
            for va, fs, buf, _ in segs:
                if va <= off < va + fs - 7:
                    struct.pack_into("<Q", buf, off - va, add & 0xffffffffffffffff); n += 1; break
        print("[+] релокаций применено: %d" % n)
    ro_patches = []
    def rseg(v):
        for s in segs:
            if s[0] <= v < s[0] + s[1]: return s
    def rd(v, n):
        s = rseg(v)
        if s: return bytes(s[2][v - s[0]: v - s[0] + n])
        o = fo(v)
        if o is None: return None
        return bytes(m[o:o + n])
    def q(v):
        b = rd(v, 8); return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None
    def d(v):
        b = rd(v, 4); return struct.unpack("<I", b)[0] if b and len(b) == 4 else None
    def wr(v, data):
        s = rseg(v)
        if not s: die("запись вне записываемых сегментов: %x" % v)
        s[2][v - s[0]: v - s[0] + len(data)] = data
    def wq(v, x): wr(v, struct.pack("<Q", x & 0xffffffffffffffff))
    pat = struct.pack("<Q", NU); blob = None
    for va, fs, buf, _ in segs:
        p = 0
        while True:
            p = buf.find(pat, p)
            if p < 0: break
            if p % 8 == 0:
                v = va + p
                if q(v - 0x40) == NI and (q(v + 0x58) == NT) and (q(v + 0x10) or 0) < 100000:
                    blob = v - 0x50; break
            p += 1
        if blob: break
    if not blob: die("блок регистраций не найден (профиль не подходит этой сборке)")
    W = [q(blob + 8 * i) for i in range(29)]
    lo = lambda x: x & 0xffffffff; hi = lambda x: x >> 32
    chk = [
        ("cgmCount==images", W[2] == NI), ("unresCount", W[10] == NU), ("typedefs q", W[21] == NT),
        ("typedefs pair", lo(W[17]) == NT), ("genericClasses array after blob", W[16] == blob + 29 * 8)]
    for n_, ok in chk: print(("[+] " if ok else "[-] ") + n_)
    if not all(ok for _, ok in chk): die("проверка блока не прошла")
    A, B, C, Dd, E, F, G, H, I, J, K, L, M, N, O = (W[1 - 1], W[3], W[4], W[6], W[8], W[9], W[11], W[13], W[15], W[16],
                                                      W[19], W[20], W[22], W[24], W[27])
    c_invoker, c_interop = lo(W[5]), hi(W[5]); c_gmp = W[7]; c_rpw = W[12]
    c_types = hi(W[17]); c_gmt = W[18]; c_ginst = W[23]; c_mspec = W[25]; c_gcls = W[28]
    print("[*] counts: gmp=%d invokers=%d rpw=%d interop=%d types=%d gmt=%d mspec=%d ginst=%d gcls=%d" %
          (c_gmp, c_invoker, c_rpw, c_interop, c_types, c_gmt, c_mspec, c_ginst, c_gcls))
    MOD = {0: 0x78, 1: 0x08, 2: 0x00, 3: 0x80, 4: 0x10, 5: 0x20, 6: 0x18, 7: 0x38, 8: None, 9: None, 10: None,
           11: None, 12: 0x30, 13: 0x40, 14: 0x70, 15: 0x58, 16: 0x68}
    good = 0; dropped = []; zarr = []
    for i in range(NI):
        mo = q(C + 8 * i); old = [q(mo + 8 * k) for k in range(17)]
        new = [(old[MOD[k] // 8] if MOD[k] is not None else 0) for k in range(17)]
        nm = rd(new[0], 64) or b""; nm = nm.split(b"\0")[0]
        if nm.endswith(b".dll"): good += 1
        for a_, c_ in ((2, 1), (4, 3)):
            if new[a_] and rd(new[a_], 8) is None:
                dropped.append(nm.decode(errors="replace"))
                cnt = new[c_] if 0 < new[c_] < 500000 else 0
                new[a_] = 0; new[c_] = cnt
                if cnt: zarr.append((mo, a_, cnt))
        for k in range(17): wq(mo + 8 * k, new[k])
    print("[+] CodeGenModule переставлено: %d, имён *.dll: %d" % (NI, good))
    if dropped: print("[!] массивы в .bss (в файле пусты), сброшены: %s" % ", ".join(sorted(set(dropped))))
    if good < NI * 0.98: die("имена модулей не распознаны")
    tl = [q(O + 8 * i) for i in range(c_types)]
    TS = set(tl); AS = set(); GS = set(); GI = set()
    for i in range(c_gcls): GS.add(q(J + 8 * i))
    for i in range(c_ginst): GI.add(q(N + 8 * i))
    queue = list(TS) + [q(g) for g in GS]
    TS |= {q(g) for g in GS}
    for gi in GI:
        argc = q(gi); argv = q(gi + 8)
        for k in range(argc):
            t = q(argv + 8 * k)
            if t and t not in TS: TS.add(t); queue.append(t)
    seen = set(TS)
    while queue:
        a = queue.pop()
        b, dt = q(a), q(a + 8); ty = (b >> 8) & 0xff
        nxt = []
        if ty in (0x0f, 0x1d): nxt.append(dt)
        elif ty == 0x14: AS.add(dt); nxt.append(q(dt + 0x20))
        elif ty == 0x15:
            if dt not in GS: GS.add(dt)
            nxt.append(q(dt))
            gi = q(dt + 0x10)
            if gi and gi not in GI:
                GI.add(gi)
                for k in range(q(gi)): nxt.append(q(q(gi + 8) + 8 * k))
        for x in nxt:
            if x and x not in seen: seen.add(x); TS.add(x); queue.append(x)
    print("[*] объектов: Il2CppType=%d GenericClass=%d ArrayType=%d" % (len(TS), len(GS), len(AS)))
    edits = []
    for a in TS:
        b, dt = q(a), q(a + 8)
        attrs = (b >> 16) & 0xffff; typ = (b >> 8) & 0xff; b0 = b & 0xff
        nb = attrs | (typ << 16) | ((b0 & 0x1f) << 24) | (((b0 >> 7) & 1) << 29) | (((b0 >> 5) & 1) << 30) | (((b0 >> 6) & 1) << 31)
        edits.append((a, struct.pack("<QII", dt, nb, 0)))
    for g in GS:
        q0, q1, q2, q3 = [q(g + 8 * k) for k in range(4)]
        edits.append((g, struct.pack("<QQQQ", q0, q2, q1, q3)))
    for a in AS:
        o = [q(a + 8 * k) for k in range(5)]
        edits.append((a, struct.pack("<QQQQQ", o[4], o[3] & 0xff, o[0], o[1], 0)))
    for a, data in edits: wr(a, data)
    def ro_rows(base, n, size, fn):
        o = fo(base); buf = bytearray(m[o:o + n * size])
        for i in range(n):
            r = struct.unpack_from("<" + "I" * (size // 4), buf, i * size)
            struct.pack_into("<" + "I" * (size // 4), buf, i * size, *fn(r))
        ro_patches.append((o, bytes(buf)))
    ro_rows(K, c_mspec, 12, lambda r: (r[0], r[2], r[1]))
    ro_rows(M, c_gmt, 16, lambda r: (r[0], r[3], r[1], r[2]))
    print("[+] methodSpecs и genericMethodTable исправлены")
    maxva = max(va + ms for off, va, fs, ms, fl in loads)
    NEWVA = (maxva + 0x100000) & ~0xfff
    code = [c_rpw, H, c_gmp, B, G, c_invoker, E, NU, A, Dd, F, c_interop, 0, 0, 0, NI, C]
    meta = [c_gcls, J, c_ginst, N, c_gmt, M, c_types, O, c_mspec, K, NT, I, NT, L, 0, 0]
    zsize = sum(((c * 8 + 15) & ~15) for _, _, c in zarr)
    seg = bytearray(0x1000 + zsize)
    struct.pack_into("<" + "Q" * 17, seg, 0, *code)
    struct.pack_into("<" + "Q" * 16, seg, 0x100, *meta)
    zp = NEWVA + 0x1000
    for mo, a_, c in zarr:
        wq(mo + 8 * a_, zp); zp += (c * 8 + 15) & ~15
    print("[*] копирую библиотеку...")
    shutil.copyfile(lib, outf)
    with open(outf, "r+b") as o:
        if 8 in didx:
            dva = dynp[1] + didx[8] + 8
            if rseg(dva): wq(dva, 0)
            else: ro_patches.append((fo(dva), struct.pack("<Q", 0)))
        for va, fs, buf, off in segs:
            o.seek(off); o.write(bytes(buf))
        for off, data in ro_patches:
            o.seek(off); o.write(data)
        size = o.seek(0, 2); newoff = (size + 0xfff) & ~0xfff
        o.write(b"\0" * (newoff - size)); o.write(seg)
        cand = [p for p in phdrs if p[1] in (4, 0x6474e551, 0x70000001)]
        if not cand: die("нет свободной записи в таблице program headers")
        i = cand[0][0]
        o.seek(phoff + i * pe)
        o.write(struct.pack("<IIQQQQQQ", 1, 6, newoff, NEWVA, NEWVA, len(seg), len(seg), 0x1000))
    print("[+] готово: %s" % outf)
    print("    CodeRegistration     = 0x%x" % NEWVA)
    print("    MetadataRegistration = 0x%x" % (NEWVA + 0x100))

if __name__ == "__main__":
    main()
