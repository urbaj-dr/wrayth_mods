#!/usr/bin/env python3
"""
patch_wrayth.py - Wrayth.exe fixes in  the "leaky pen" (GDI) and the
"progressBar leak" (vitals-bar memory leak).

USAGE
    python patch_wrayth.py Wrayth.exe Wrayth_patched.exe
    python patch_wrayth.py --dry Wrayth.exe x.exe        # check only, write nothing

    --no-gdi      skip the leaky-pen fix
    --no-leak     skip the progressBar fix
    --no-laa      do NOT enable the LARGEADDRESSAWARE flag

The input must be the original untouched exe (SHA-256 below).  The output path must differ from
the input path.  Nothing is written unless every check passes, and the written file is
read back and compared.

---------------------------------------------------------------------------------
FIX 1 - THE LEAKY PEN  (GDI handles)
  The "hand" window class WndProc (VA 0x42a210) calls CreatePen on every WM_PAINT when
  an item/spell is in the hand, selects the pen into the paint DC and never restores the
  old pen or deletes the new one.  After about 10,000 leaked handles Wrayth crashes.
  The patch keeps the old pen and the new pen in two stack slots ([esp+0x3c],
  [esp+0x40], zeroed on entry to the paint path).  After drawing, it reselects the old
  pen (SelectObject returns the new pen) and deletes the new pen; if the select failed
  it deletes the new pen directly.  Three code edits plus two code caves in .text
  padding.  (Behaviour change: a failed SelectObject no longer builds the error object
  the original code built there.)

FIX 2 - THE PROGRESSBAR LEAK  (heap growth, about 20 KB per vitals update)
  Every dialogData message re-applies the skin and rebuilds the progressBars.  Wrayth's
  GetChild (0x494f50) asks a parent element for a named child.  The engine's lookup
  (vtable slot 0x50) returns the child with one reference added, and the caller owns that
  reference.  Wrayth keeps one 0x50-byte "descriptor" per child in a registry (hash_map
  0x578b38, keyed by element address):
    * no descriptor yet -> the new descriptor takes over the reference (correct);
    * descriptor exists -> GetChild returns it and never releases the reference it was
      just given.  That is the leak: each looked-up bar element (rt, rtbar, rtnum,
      rtBarNum) keeps one stray reference, so its whole tree is never freed.
  Measured: the "descriptor exists" path was taken once per descriptor created (2,121
  of 2,121 in a 100-update run) and committed heap growth fell from about 1.7 MB to
  68 KB per 100 updates.
  Descriptors themselves also piled up (nothing disposed the ones built for the vitals
  bars), so four hooks are installed, none of which relocates an instruction:
    A. ctor call at 0x49510c     run the real ctor, then record {parent, child}.
    B. call 0x424ca0 at 0x414b3b before a window descriptor is destroyed, dispose every
                                 recorded child of it (grandchildren first).
    C. std::string::assign at 0x49514a
                                 after a child is named, dispose any OTHER recorded child
                                 of the same parent with the same name (a stale
                                 predecessor).
    D. lookup call at 0x4950d9   when it finds an existing descriptor, release the extra
                                 reference.
  Disposal of a child is exactly what 0x424ca0 does for a window:
        if (child->+0x24) { 0x495190(child, 0);  child->vtbl[0](child, 1); }
  Code, counters and the table live in a NEW section (.lkfix); everything is addressed
  relative to `call $+0 / pop reg`, so a rebase is harmless.  All branch compares are
  unsigned, so the image is safe above 2 GB.

LAA (activates by default; --no-laa to skip)
  Sets IMAGE_FILE_LARGE_ADDRESS_AWARE so 64-bit Windows allows 4 GB instead of 2 GB.

READOUT (WinDbg):  dd Wrayth+<offset printed at the end> l5
    [0] children recorded   [1] children disposed   [2] table-full events
    [3] stale same-name children replaced
    [4] lookups that hit an existing descriptor (one stray reference released each)
  Healthy: [2] stays 0, [0]-[1] settles instead of growing, [4] tracks [0].

---------------------------------------------------------------------------------
"""
import argparse
import hashlib
import os
import struct
import sys
import tempfile

IMAGE_BASE = 0x400000
EXPECTED_SHA256 = "550cc63fa5b87b8421c01bf34a8c7a5fd744331d9af7bb5ea034fd2a17421415"
EXPECTED_SIZE = 1450992


class PatchError(Exception):
    pass


# ====================================================================== PE helpers

def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def align(v, a):
    return (v + a - 1) // a * a


def parse(d):
    if d[:2] != b'MZ':
        raise PatchError('not an MZ file')
    pe = u32(d, 0x3c)
    if d[pe:pe + 4] != b'PE\0\0':
        raise PatchError('not a PE file')
    if struct.unpack_from('<H', d, pe + 4)[0] != 0x14C:
        raise PatchError('not a 32-bit x86 PE')
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    soh = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from('<H', d, opt)[0] != 0x10b:
        raise PatchError('not PE32')
    info = dict(pe=pe, nsec=nsec, opt=opt, soh=soh,
                base=u32(d, opt + 28), salign=u32(d, opt + 32), falign=u32(d, opt + 36),
                size_of_image=u32(d, opt + 56), size_of_headers=u32(d, opt + 60))
    tab = opt + soh
    secs = []
    for i in range(nsec):
        o = tab + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', d, o + 8)
        secs.append(dict(name=d[o:o + 8].rstrip(b'\0').decode('latin1'),
                         va=info['base'] + va, rva=va, vsize=vs, rsize=rs, rptr=rp,
                         ch=u32(d, o + 36), hdr=o))
    info['secs'] = secs
    info['tab'] = tab
    return info


def foff(info, va, length=1):
    """File offset of a virtual address (must lie inside a section's raw data)."""
    ordered = sorted(info['secs'], key=lambda s: s['va'])
    for i, s in enumerate(ordered):
        lo = s['va']
        hi = lo + align(s['vsize'], 0x1000)
        if i + 1 < len(ordered):
            hi = min(hi, ordered[i + 1]['va'])
        if lo <= va < hi:
            off = va - lo
            if off + length > s['rsize']:
                raise PatchError('VA %#x +%d is past raw data of %s' % (va, length, s['name']))
            return s['rptr'] + off
    raise PatchError('VA %#x is in no section' % va)


# ====================================================================== FIX 1: GDI

GDI_CAVE1_VA = 0x51A41C
GDI_CAVE2_VA = 0x51A480

# Original bytes, fixed reference values (NOT read from the input file).
GDI_ORIG_P1 = bytes.fromhex(      # test eax,eax; jne; <29-byte error path>; jmp 0x42a4e7
    "85c0752d83ec1c8bcc896424486890e25100ff1534b55100e8cd55ffff83c41ceb0f")
GDI_ORIG_P2A = bytes.fromhex("8d4c245051")        # lea ecx,[esp+0x50]; push ecx
GDI_ORIG_P2B = bytes.fromhex("8d8c24b4000000")    # lea ecx,[esp+0xb4]
assert len(GDI_ORIG_P1) == 34 and len(GDI_ORIG_P2A) == 5 and len(GDI_ORIG_P2B) == 7


def gdi_patches(orig):
    """Return the list of GDI patch dicts, validated against the original bytes."""
    patches = []

    def need(off, want, label):
        got = bytes(orig[off:off + len(want)])
        if got != want:
            raise PatchError('%s: bytes at file offset %#x are %s, expected %s'
                             % (label, off, got.hex(), want.hex()))

    # Patch 1: save old pen + new pen (34 bytes at 0x2A4B6, VA 0x42A4B6)
    p1_off = 0x2A4B6
    need(p1_off, GDI_ORIG_P1, 'GDI patch 1')
    p1_new = (b'\x89\x44\x24\x3c'          # mov [esp+0x3c], eax   old pen (SelectObject)
              b'\x89\x7c\x24\x40'          # mov [esp+0x40], edi   new pen (CreatePen)
              b'\xeb\x27'                  # jmp 0x42a4e7
              + b'\x90' * 24)
    assert len(p1_new) == 34
    assert 0x42A4C0 + 0x27 == 0x42A4E7   # jmp ends at 0x42A4C0
    patches.append(dict(name='GDI patch 1: save old pen [esp+0x3c] + new pen [esp+0x40]',
                        off=p1_off, va=0x42A4B6, orig=GDI_ORIG_P1, new=p1_new))

    # Patch 2a: jump to cave 2 (5 bytes at 0x2A34F)
    p2a_off = 0x2A34F
    need(p2a_off, GDI_ORIG_P2A, 'GDI patch 2a')
    p2a_new = b'\xe9' + struct.pack('<i', GDI_CAVE2_VA - (0x42A34F + 5))
    patches.append(dict(name='GDI patch 2a: jmp to cave 2 (zero the pen slots)',
                        off=p2a_off, va=0x42A34F, orig=GDI_ORIG_P2A, new=p2a_new))

    # Patch 2b: jump to cave 1 (7 bytes at 0x2A7CD)
    p2b_off = 0x2A7CD
    need(p2b_off, GDI_ORIG_P2B, 'GDI patch 2b')
    p2b_new = b'\xe9' + struct.pack('<i', GDI_CAVE1_VA - (0x42A7CD + 5)) + b'\x90\x90'
    patches.append(dict(name='GDI patch 2b: jmp to cave 1 (pen cleanup)',
                        off=p2b_off, va=0x42A7CD, orig=GDI_ORIG_P2B, new=p2b_new))

    # Cave 1: pen cleanup
    c1 = bytearray()
    c1 += b'\x8b\x44\x24\x3c'                 # 0:  mov eax, [esp+0x3c]      old pen
    c1 += b'\x85\xc0'                         # 4:  test eax, eax
    c1 += b'\x74\x11'                         # 6:  je case B (25)
    c1 += b'\x50'                             # 8:  push eax (old pen)
    c1 += b'\x56'                             # 9:  push esi (HDC)
    c1 += b'\xff\x15\x3c\xb0\x51\x00'        # 10: call [SelectObject]
    c1 += b'\x50'                             # 16: push eax (the new pen it returns)
    c1 += b'\xff\x15\xf0\xb0\x51\x00'        # 17: call [DeleteObject]
    c1 += b'\xeb\x0f'                         # 23: jmp lea (40)
    c1 += b'\x8b\x44\x24\x40'                 # 25: mov eax, [esp+0x40]      new pen, never selected
    c1 += b'\x85\xc0'                         # 29: test eax, eax
    c1 += b'\x74\x07'                         # 31: je lea (40)
    c1 += b'\x50'                             # 33: push eax
    c1 += b'\xff\x15\xf0\xb0\x51\x00'        # 34: call [DeleteObject]
    assert len(c1) == 40
    assert 6 + 2 + 0x11 == 25 and 23 + 2 + 0x0f == 40 and 31 + 2 + 0x07 == 40
    c1 += b'\x8d\x8c\x24\xb4\x00\x00\x00'    # 40: lea ecx, [esp+0xb4]      (displaced original)
    c1 += b'\xc7\x84\x24\x58\x01\x00\x00\xff\xff\xff\xff'   # mov [esp+0x158], -1  (orig.)
    c1 += b'\xff\x15\x2c\xb4\x51\x00'        # call [string::~string]       (original)
    back = GDI_CAVE1_VA + len(c1)
    c1 += b'\xe9' + struct.pack('<i', 0x42A7E5 - (back + 5))
    if GDI_CAVE1_VA + len(c1) > GDI_CAVE2_VA:
        raise PatchError('GDI cave 1 overlaps cave 2')
    c1_off = GDI_CAVE1_VA - IMAGE_BASE
    zero = bytes(len(c1))
    need(c1_off, zero, 'GDI cave 1 (must be unused zero padding)')
    patches.append(dict(name='GDI cave 1: pen cleanup (%d bytes at %#x)' % (len(c1), GDI_CAVE1_VA),
                        off=c1_off, va=GDI_CAVE1_VA, orig=zero, new=bytes(c1)))

    # Cave 2: zero the pen slots, then run the displaced instructions
    c2 = bytearray()
    c2 += b'\xc7\x44\x24\x3c\x00\x00\x00\x00'   # mov dword [esp+0x3c], 0
    c2 += b'\xc7\x44\x24\x40\x00\x00\x00\x00'   # mov dword [esp+0x40], 0
    c2 += b'\x8d\x4c\x24\x50'                   # lea ecx, [esp+0x50]   (displaced original)
    c2 += b'\x51'                               # push ecx              (displaced original)
    back2 = GDI_CAVE2_VA + len(c2)
    c2 += b'\xe9' + struct.pack('<i', 0x42A354 - (back2 + 5))
    c2_off = GDI_CAVE2_VA - IMAGE_BASE
    zero2 = bytes(len(c2))
    need(c2_off, zero2, 'GDI cave 2 (must be unused zero padding)')
    patches.append(dict(name='GDI cave 2: zero pen slots (%d bytes at %#x)' % (len(c2), GDI_CAVE2_VA),
                        off=c2_off, va=GDI_CAVE2_VA, orig=zero2, new=bytes(c2)))

    for p in patches:
        assert len(p['orig']) == len(p['new'])
    ordered = sorted((p['off'], p['off'] + len(p['new']), p['name']) for p in patches)
    for a, b in zip(ordered, ordered[1:]):
        if a[1] > b[0]:
            raise PatchError('GDI patch ranges overlap: %s / %s' % (a[2], b[2]))

    # unchanged context the patch relies on
    for label, off, want in (('CreatePen call', 0x2A48A, b'\xff\x15\x50\xb0\x51\x00'),
                             ('jne (CreatePen check)', 0x2A494, b'\x75\x1c'),
                             ('SelectObject block', 0x2A4B2, b'\x57\x56\xff\xd5')):
        need(off, want, 'GDI context ' + label)
    return patches


def apply_gdi(data):
    patches = gdi_patches(bytes(data))
    for p in patches:
        n = len(p['new'])
        data[p['off']:p['off'] + n] = p['new']
        if bytes(data[p['off']:p['off'] + n]) != p['new']:
            raise PatchError('write verification failed: ' + p['name'])
        print('  OK  %s   (VA %#x, %d bytes)' % (p['name'], p['va'], n))
    return patches


# ====================================================================== LAA

def apply_laa(data):
    info = parse(data)
    off = info['pe'] + 4 + 18
    ch = struct.unpack_from('<H', data, off)[0]
    if ch & 0x20:
        print('  --  already large-address-aware; unchanged')
        return
    struct.pack_into('<H', data, off, ch | 0x20)
    print('  OK  LAA flag set (Characteristics %#06x -> %#06x)' % (ch, ch | 0x20))


# ====================================================================== FIX 2: progressBar leak

SITE_CREATE = 0x0049510C        # call 0x494e90  (descriptor ctor, in GetChild)
SITE_DISPOSE = 0x00414B3B       # call 0x424ca0  (window dtor disposing its descriptor)
SITE_ASSIGN = 0x0049514A        # 8d 4e 04 ff 15 <slot>: lea ecx,[esi+4] / call [slot]
ASSIGN_RESUME = 0x00495153      # first byte after the original `call [slot]`
SITE_FIND = 0x004950D9          # call 0x4947c0 (registry lookup by element) in GetChild
REAL_CTOR = 0x00494E90
REAL_FIND = 0x004947C0
REAL_DETACH = 0x00495190        # SetTarget(desc, 0): erase registry entry + release element
REAL_DESTROY = 0x00424CA0       # window-descriptor destroy

LEAK_SIGNATURES = [
    (REAL_CTOR,        bytes.fromhex('6aff68')),
    (REAL_DETACH,      bytes.fromhex('83ec1456578bf9')),
    (REAL_DESTROY,     bytes.fromhex('568b742408837e2400')),
    (REAL_FIND,        bytes.fromhex('83ec08535556')),
    (SITE_CREATE - 7,  bytes.fromhex('8b552051528bc8e8')),
    (SITE_FIND - 1,    bytes.fromhex('52e8')),
    (SITE_DISPOSE - 7, bytes.fromhex('8b0da48c570050e8')),
    (SITE_ASSIGN - 1,  bytes.fromhex('508d4e04ff15')),       # + imm32 slot, then:
    (ASSIGN_RESUME,    bytes.fromhex('57')),                  # push edi
]
LEAK_CALL_SITES = ((SITE_CREATE, REAL_CTOR), (SITE_DISPOSE, REAL_DESTROY), (SITE_FIND, REAL_FIND))

NEW_SEC_NAME = b'.lkfix\0\0'
NEW_SEC_CHARS = 0xE0000060      # CODE | INITIALIZED | EXECUTE | READ | WRITE
ENTRIES = 16384


def _keystone():
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32
    except ImportError:
        raise PatchError('the progress-bar fix needs keystone-engine:  pip install keystone-engine'
                         '\n(or run with --no-leak)')
    return Ks(KS_ARCH_X86, KS_MODE_32)


class Code:
    """Tiny assembler.  Bodies come from keystone; jumps/calls between our own routines are
    always rel32 so sizes cannot change.  Position independence: `call $+0 / pop reg`."""

    REG_MODRM = {'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esi': 6, 'edi': 7}

    def __init__(self, ks, va):
        self.ks = ks
        self.va = va
        self.buf = bytearray()
        self.labels = {}
        self.fix = []

    @property
    def pc(self):
        return self.va + len(self.buf)

    def ins(self, text):
        enc, _ = self.ks.asm(text, self.pc)
        if not enc:
            raise PatchError('assembler produced nothing for: ' + text)
        self.buf += bytes(enc)

    def label(self, name):
        assert name not in self.labels, name
        self.labels[name] = self.pc

    def _rel(self, opbytes, name):
        self.buf += opbytes
        self.fix.append((len(self.buf), name))
        self.buf += b'\0\0\0\0'

    def jmp(self, name):  self._rel(b'\xe9', name)
    def call(self, name): self._rel(b'\xe8', name)
    def je(self, name):   self._rel(b'\x0f\x84', name)
    def jne(self, name):  self._rel(b'\x0f\x85', name)
    def jb(self, name):   self._rel(b'\x0f\x82', name)
    def jae(self, name):  self._rel(b'\x0f\x83', name)

    def here(self, reg):
        """call $+0 / pop reg -> reg = VA of the instruction after the call."""
        self.buf += b'\xe8\x00\x00\x00\x00'
        h = self.pc
        self.buf += {'eax': b'\x58', 'ecx': b'\x59', 'edx': b'\x5a',
                     'ebx': b'\x5b', 'esi': b'\x5e', 'edi': b'\x5f'}[reg]
        return h

    def lea_from(self, dst, src, h, target):
        modrm = 0x80 | (self.REG_MODRM[dst] << 3) | self.REG_MODRM[src]
        self.buf += b'\x8d' + bytes([modrm]) + struct.pack('<i', target - h)

    def lock_inc(self, src, h, target):
        modrm = 0x80 | self.REG_MODRM[src]
        self.buf += b'\xf0\xff' + bytes([modrm]) + struct.pack('<i', target - h)

    def finish(self):
        for pos, name in self.fix:
            tgt = self.labels[name]
            struct.pack_into('<i', self.buf, pos, tgt - (self.va + pos + 4))
        return bytes(self.buf)


def build_leak_code(ks, code_va, cnt_va, tab_va, n_entries, slot_va):
    INS, DISP, OVF, REPL = cnt_va, cnt_va + 4, cnt_va + 8, cnt_va + 12
    HIT = cnt_va + 16
    tend = tab_va + 8 * n_entries
    c = Code(ks, code_va)

    # ---- name_eq(a, b): cdecl.  1 if the two descriptors' std::string names are equal
    #      (MSVC8 layout: buf/ptr +8, size +0x18, cap +0x1c).  Preserves esi/edi.
    c.label('name_eq')
    c.ins('push esi'); c.ins('push edi')
    c.ins('mov esi, dword ptr [esp+0xc]')
    c.ins('mov edi, dword ptr [esp+0x10]')
    c.ins('mov ecx, dword ptr [esi+0x18]')
    c.ins('cmp ecx, dword ptr [edi+0x18]')
    c.jne('ne_no')
    c.ins('test ecx, ecx')
    c.je('ne_yes')
    c.ins('lea eax, [esi+8]')
    c.ins('cmp dword ptr [esi+0x1c], 0x10')
    c.jb('ne_a')
    c.ins('mov eax, dword ptr [eax]')
    c.label('ne_a')
    c.ins('lea edx, [edi+8]')
    c.ins('cmp dword ptr [edi+0x1c], 0x10')
    c.jb('ne_b')
    c.ins('mov edx, dword ptr [edx]')
    c.label('ne_b')
    c.ins('mov esi, eax')
    c.ins('mov edi, edx')
    c.ins('cld')
    c.ins('repe cmpsb')
    c.jne('ne_no')
    c.label('ne_yes')
    c.ins('mov eax, 1')
    c.jmp('ne_out')
    c.label('ne_no')
    c.ins('xor eax, eax')
    c.label('ne_out')
    c.ins('pop edi'); c.ins('pop esi')
    c.ins('ret')

    # ---- disp_one(child): cdecl.  Dispose one child and everything recorded under it.
    #      Preserves ebx/esi/edi/ebp.
    c.label('disp_one')
    c.ins('push dword ptr [esp+4]')
    c.call('disp')                              # grandchildren first
    c.ins('add esp, 4')
    c.ins('mov eax, dword ptr [esp+4]')
    c.ins('cmp dword ptr [eax+0x24], 0')        # same guard 0x424ca0 uses
    c.je('do_done')
    c.ins('push eax')
    c.ins('push 0')
    c.ins('mov ecx, eax')
    h = c.here('edx'); c.lea_from('edx', 'edx', h, REAL_DETACH)
    c.ins('call edx')                           # 0x495190(child, 0)   ret 4
    c.ins('pop eax')
    c.ins('mov ecx, eax')
    c.ins('mov edx, dword ptr [eax]')
    c.ins('mov edx, dword ptr [edx]')
    c.ins('push 1')
    c.ins('call edx')                           # child->vtbl[0](child, 1)   ret 4
    h = c.here('edx'); c.lock_inc('edx', h, DISP)
    c.label('do_done')
    c.ins('ret')

    # ---- disp(parent): cdecl.  Dispose every recorded child of `parent`.
    c.label('disp')
    c.ins('push ebx'); c.ins('push esi'); c.ins('push edi')
    c.ins('mov edi, dword ptr [esp+0x10]')
    h = c.here('ebx')
    c.lea_from('esi', 'ebx', h, tab_va)
    c.lea_from('ebx', 'ebx', h, tend)
    c.label('d_loop')
    c.ins('cmp esi, ebx')
    c.jae('d_done')
    c.ins('cmp dword ptr [esi], edi')
    c.jne('d_next')
    c.ins('mov eax, dword ptr [esi+4]')
    c.ins('mov dword ptr [esi], 0')            # free the slot BEFORE recursing/destroying
    c.ins('mov dword ptr [esi+4], 0')
    c.ins('test eax, eax')
    c.je('d_next')
    c.ins('push eax')
    c.call('disp_one')
    c.ins('add esp, 4')
    c.label('d_next')
    c.ins('add esi, 8')
    c.jmp('d_loop')
    c.label('d_done')
    c.ins('pop edi'); c.ins('pop esi'); c.ins('pop ebx')
    c.ins('ret')

    # ---- sweep: esi = child just named, ebp = its parent.  Dispose other recorded
    #      children of ebp that carry the same name.  Preserves ebx/esi/edi/ebp.
    c.label('sweep')
    c.ins('push ebx'); c.ins('push edi')
    c.ins('cmp dword ptr [esi+0x18], 0')       # empty name: never match on it
    c.je('s_done')
    h = c.here('ebx')
    c.lea_from('edi', 'ebx', h, tab_va)
    c.lea_from('ebx', 'ebx', h, tend)
    c.label('s_loop')
    c.ins('cmp edi, ebx')
    c.jae('s_done')
    c.ins('cmp dword ptr [edi], ebp')
    c.jne('s_next')
    c.ins('mov ecx, dword ptr [edi+4]')
    c.ins('test ecx, ecx')
    c.je('s_next')
    c.ins('cmp ecx, esi')                       # never the child we just named
    c.je('s_next')
    c.ins('push esi')
    c.ins('push ecx')
    c.call('name_eq')
    c.ins('add esp, 8')
    c.ins('test eax, eax')
    c.je('s_next')
    c.ins('mov eax, dword ptr [edi+4]')
    c.ins('mov dword ptr [edi], 0')
    c.ins('mov dword ptr [edi+4], 0')
    c.ins('push eax')
    c.call('disp_one')
    c.ins('add esp, 4')
    h = c.here('edx'); c.lock_inc('edx', h, REPL)
    c.label('s_next')
    c.ins('add edi, 8')
    c.jmp('s_loop')
    c.label('s_done')
    c.ins('pop edi'); c.ins('pop ebx')
    c.ins('ret')

    # ---- stub_assign: replaces the 5 bytes `lea ecx,[esi+4] / ff 15` at SITE_ASSIGN.
    #      entry: [esp]=SITE_ASSIGN+5, [esp+4]=name string ptr (pushed by the caller),
    #             esi = child descriptor, ebp = parent descriptor, edi live.
    c.label('stub_assign')
    c.ins('add dword ptr [esp], 4')             # resume after the ORIGINAL 6-byte call
    c.ins('lea ecx, [esi+4]')
    c.ins('push dword ptr [esp+4]')
    h = c.here('edx'); c.lea_from('edx', 'edx', h, slot_va)
    c.ins('call dword ptr [edx]')               # original std::string::assign (pops 1 arg)
    c.call('sweep')
    c.ins('ret 4')                              # pops the caller's pushed arg, like assign did

    # ---- stub_dispose: replaces `call 0x424ca0` at SITE_DISPOSE
    #      entry: [esp]=ret [esp+4]=desc, ecx=this
    c.label('stub_dispose')
    c.ins('push ecx')
    c.ins('push dword ptr [esp+8]')
    c.call('disp')
    c.ins('add esp, 4')
    c.ins('pop ecx')
    h = c.here('edx'); c.lea_from('edx', 'edx', h, REAL_DESTROY)
    c.ins('jmp edx')

    # ---- stub_create: replaces `call 0x494e90` at SITE_CREATE
    #      entry: [esp]=ret [esp+4]=a1 [esp+8]=a2, ecx=this(new), ebp=parent descriptor
    c.label('stub_create')
    c.ins('push dword ptr [esp+8]')
    c.ins('push dword ptr [esp+8]')
    h = c.here('edx'); c.lea_from('eax', 'edx', h, REAL_CTOR)
    c.ins('call eax')                           # real ctor: pops its 2 args, eax = this
    h = c.here('edx')
    c.lea_from('ecx', 'edx', h, tab_va)
    c.lea_from('edx', 'edx', h, tend)
    c.label('c_loop')
    c.ins('cmp dword ptr [ecx], 0')
    c.je('c_found')
    c.ins('add ecx, 8')
    c.ins('cmp ecx, edx')
    c.jb('c_loop')
    h = c.here('edx'); c.lock_inc('edx', h, OVF)      # table full: leak this one as before
    c.ins('ret 8')
    c.label('c_found')
    c.ins('mov dword ptr [ecx+4], eax')
    c.ins('mov dword ptr [ecx], ebp')            # parent written last = slot becomes live
    h = c.here('edx'); c.lock_inc('edx', h, INS)
    c.ins('ret 8')

    # ---- stub_find: replaces `call 0x4947c0` at SITE_FIND (GetChild, after vtbl[0x50]).
    #      entry: [esp]=ret  [esp+4]=element returned by the engine (carries one AddRef).
    #      cdecl; eax = existing descriptor or 0.  When a descriptor already exists
    #      GetChild returns it and DROPS the reference it just took -- release it here.
    c.label('stub_find')
    c.ins('push dword ptr [esp+4]')
    h = c.here('edx'); c.lea_from('eax', 'edx', h, REAL_FIND)
    c.ins('call eax')
    c.ins('add esp, 4')
    c.ins('test eax, eax')
    c.je('sf_ret')
    c.ins('mov ecx, dword ptr [esp+4]')
    c.ins('test ecx, ecx')
    c.je('sf_ret')
    c.ins('push eax')
    c.ins('mov edx, dword ptr [ecx]')
    c.ins('push ecx')
    c.ins('call dword ptr [edx+8]')             # element->Release()  (stdcall)
    h = c.here('edx'); c.lock_inc('edx', h, HIT)
    c.ins('pop eax')
    c.label('sf_ret')
    c.ins('ret')

    return c.finish(), c.labels


def apply_leak(data):
    """Add the .lkfix section and hook the call sites, in place.  Returns a dict."""
    entries = ENTRIES
    ks = _keystone()
    info = parse(data)
    if info['base'] != IMAGE_BASE:
        raise PatchError('image base %#x, expected %#x' % (info['base'], IMAGE_BASE))
    if any(s['name'] == '.lkfix' for s in info['secs']):
        raise PatchError('already has a .lkfix section -- start from the pristine original')

    for va, want in LEAK_SIGNATURES:
        o = foff(info, va, len(want))
        got = bytes(data[o:o + len(want)])
        if got != want:
            raise PatchError('bytes at %#x are %s, expected %s (wrong build, or already patched)'
                             % (va, got.hex(), want.hex()))
    for site, tgt in LEAK_CALL_SITES:
        o = foff(info, site, 5)
        if data[o] != 0xE8:
            raise PatchError('site %#x is not a call' % site)
        rel = struct.unpack_from('<i', data, o + 1)[0]
        if site + 5 + rel != tgt:
            raise PatchError('site %#x calls %#x, expected %#x (already patched?)'
                             % (site, site + 5 + rel, tgt))
    slot_va = u32(data, foff(info, SITE_ASSIGN + 5, 4))
    if not (IMAGE_BASE <= slot_va < IMAGE_BASE + info['size_of_image']):
        raise PatchError('assign slot %#x outside the image' % slot_va)

    sec_va_off = align(max(max(s['vsize'], s['rsize']) + s['rva'] for s in info['secs']),
                       info['salign'])
    cnt_va = IMAGE_BASE + sec_va_off
    tab_va = cnt_va + 0x20
    code_va = align(tab_va + 8 * entries, 16)
    code, labels = build_leak_code(ks, code_va, cnt_va, tab_va, entries, slot_va)
    raw_len = align(code_va + len(code) - cnt_va, info['falign'])
    vsize = align(code_va + len(code) - cnt_va, info['salign'])

    hdr_end = info['tab'] + info['nsec'] * 40
    first_raw = min(s['rptr'] for s in info['secs'] if s['rptr'])
    if first_raw - hdr_end < 40 or any(data[hdr_end:hdr_end + 40]):
        raise PatchError('no room for another section header (%d free bytes)'
                         % (first_raw - hdr_end))

    file_len = align(len(data), info['falign'])
    data += b'\0' * (file_len - len(data))
    raw_off = len(data)
    blk = bytearray(raw_len)
    blk[code_va - cnt_va:code_va - cnt_va + len(code)] = code
    data += blk

    o = hdr_end
    data[o:o + 8] = NEW_SEC_NAME
    struct.pack_into('<IIIIIIHHI', data, o + 8, vsize, sec_va_off, raw_len, raw_off,
                     0, 0, 0, 0, NEW_SEC_CHARS)
    struct.pack_into('<H', data, info['pe'] + 6, info['nsec'] + 1)
    struct.pack_into('<I', data, info['opt'] + 56, sec_va_off + vsize)       # SizeOfImage
    struct.pack_into('<I', data, info['opt'] + 64, 0)                        # CheckSum

    for site, stub in ((SITE_CREATE, labels['stub_create']),
                       (SITE_DISPOSE, labels['stub_dispose']),
                       (SITE_FIND, labels['stub_find'])):
        struct.pack_into('<i', data, foff(info, site, 5) + 1, stub - (site + 5))
    # `8d 4e 04 ff 15` (5 bytes) -> `e8 rel32`.  The relocated imm32 after it is left
    # untouched and never executed (the stub resumes after it).
    so = foff(info, SITE_ASSIGN, 5)
    data[so] = 0xE8
    struct.pack_into('<i', data, so + 1, labels['stub_assign'] - (SITE_ASSIGN + 5))

    print('  OK  .lkfix section: VA %#x, vsize %#x, raw %#x  (counters %#x, table %#x x%d, code %#x, %d bytes)'
          % (cnt_va, vsize, raw_len, cnt_va, tab_va, entries, code_va, len(code)))
    for name, site in (('stub_create', SITE_CREATE), ('stub_dispose', SITE_DISPOSE),
                       ('stub_assign', SITE_ASSIGN), ('stub_find', SITE_FIND)):
        print('  OK  %-12s %#x  hooks %#x' % (name, labels[name], site))
    return dict(cnt_va=cnt_va, tab_va=tab_va, code_va=code_va, code_end=code_va + len(code),
                labels=labels, slot_va=slot_va, entries=entries)


# ====================================================================== verification

def verify(out, gdi, do_laa, leak):
    """Independent re-read of the finished image."""
    info = parse(out)
    if leak:
        s = [x for x in info['secs'] if x['name'] == '.lkfix']
        if len(s) != 1:
            raise PatchError('verify: .lkfix section missing')
        s = s[0]
        lo, hi = s['va'], s['va'] + s['vsize']
        if s['rptr'] + s['rsize'] > len(out):
            raise PatchError('verify: .lkfix raw data runs past end of file')
        if info['size_of_image'] < s['rva'] + s['vsize']:
            raise PatchError('verify: SizeOfImage too small')
        if not (lo <= leak['cnt_va'] and leak['code_end'] <= hi):
            raise PatchError('verify: counters/code outside the section')
        want = {SITE_CREATE: 'stub_create', SITE_DISPOSE: 'stub_dispose',
                SITE_FIND: 'stub_find', SITE_ASSIGN: 'stub_assign'}
        for site, name in want.items():
            o = foff(info, site, 5)
            if out[o] != 0xE8:
                raise PatchError('verify: hook at %#x is not a call' % site)
            tgt = site + 5 + struct.unpack_from('<i', out, o + 1)[0]
            if tgt != leak['labels'][name] or not (leak['code_va'] <= tgt < leak['code_end']):
                raise PatchError('verify: hook at %#x targets %#x, expected %s' % (site, tgt, name))
    for p in gdi or ():
        if bytes(out[p['off']:p['off'] + len(p['new'])]) != p['new']:
            raise PatchError('verify: %s not present in output' % p['name'])
    if do_laa and not (struct.unpack_from('<H', out, info['pe'] + 22)[0] & 0x20):
        raise PatchError('verify: LAA flag not set')


def diff_ranges(a, b):
    """Byte ranges that differ between two images (b may be longer than a)."""
    out, i, n = [], 0, min(len(a), len(b))
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


# ====================================================================== main

def main():
    ap = argparse.ArgumentParser(description='Wrayth.exe: leaky pen + progressBar leak fixes')
    ap.add_argument('src', help='original Wrayth.exe (version 1.0.1.28, SHA-256 is checked)')
    ap.add_argument('dst', help='output file (must differ from src)')
    ap.add_argument('--dry', action='store_true', help='run every check, write nothing')
    ap.add_argument('--no-gdi', action='store_true', help='skip the leaky-pen fix')
    ap.add_argument('--no-leak', action='store_true', help='skip the progressBar fix')
    ap.add_argument('--no-laa', action='store_true', help='do not set the LARGEADDRESSAWARE flag')
    a = ap.parse_args()

    try:
        if os.path.abspath(a.src).casefold() == os.path.abspath(a.dst).casefold():
            raise PatchError('input and output resolve to the same file; choose another output path')
        if a.no_gdi and a.no_leak and a.no_laa:
            raise PatchError('nothing to do (--no-gdi --no-leak --no-laa)')
        with open(a.src, 'rb') as f:
            pristine = f.read()
        sha = hashlib.sha256(pristine).hexdigest()
        print('=' * 72)
        print(' patch_wrayth.py')
        print('=' * 72)
        print('  input   %s  (%d bytes)' % (a.src, len(pristine)))
        print('  sha256  %s' % sha)
        if sha != EXPECTED_SHA256 or len(pristine) != EXPECTED_SIZE:
            raise PatchError('input is not the pristine build this patch was written for.\n'
                             '  expected sha256 %s, %d bytes' % (EXPECTED_SHA256, EXPECTED_SIZE))
        print('  pristine build verified\n')

        data = bytearray(pristine)
        leak = gdi = None
        if not a.no_gdi:
            print('Fix 1 - leaky pen (GDI):')
            gdi = apply_gdi(data)
        do_laa = not a.no_laa
        if do_laa:
            print('LAA:')
            apply_laa(data)
        if not a.no_leak:
            print('Fix 2 - progressBar leak:')
            leak = apply_leak(data)

        verify(data, gdi, do_laa, leak)

        # Only the intended places may differ from the pristine image.
        changed = diff_ranges(pristine, data)
        print('\n  changed ranges inside the original file (offset, length):')
        for lo, hi in changed:
            print('    %#08x  %4d' % (lo, hi - lo))
        if len(data) > len(pristine):
            print('    + %d bytes appended (.lkfix section)' % (len(data) - len(pristine)))

        if a.dry:
            print('\n--dry: all checks passed; nothing written.')
            return 0

        d = os.path.dirname(os.path.abspath(a.dst)) or '.'
        fd, tmp = tempfile.mkstemp(prefix='.wrayth_', suffix='.tmp', dir=d)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            with open(tmp, 'rb') as f:
                if f.read() != bytes(data):
                    raise PatchError('read-back verification failed')
            os.replace(tmp, a.dst)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        print('\n' + '=' * 72)
        print(' ALL CHECKS PASSED -- wrote %s' % a.dst)
        print('=' * 72)
        print('  size    %d bytes' % len(data))
        print('  sha256  %s' % hashlib.sha256(data).hexdigest())
        print('  sha1    %s' % hashlib.sha1(data).hexdigest())
        if leak:
            print('\n  READOUT (WinDbg):  dd Wrayth+%#x l5' % (leak['cnt_va'] - IMAGE_BASE))
            print('    [0] recorded  [1] disposed  [2] table-full  [3] stale replaced  [4] lookup hits')
        return 0
    except PatchError as e:
        print('\nREFUSED: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())