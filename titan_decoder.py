#!/usr/bin/env python3
"""
Titan Decoder Engine

MIT License

Copyright (c) 2025 Joe Schwen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

NOTE TO USERS:
This is a moderately sophisticated decoding engine for text and binary payloads.
While it can handle multiple encodings, GZIP/ZIP detection, lenient decompression, and both
manual and auto-decoding, there may still be bugs, errors, or unexpected behavior.
Short payloads may not decode correctly, and extremely large or corrupted payloads may fail
or produce truncated output.

Use at your own discretion. The author is not responsible for misuse or any issues arising
from running this software.
"""

import base64, binascii, sys, string, re, urllib.parse, io, zipfile, codecs, gzip, zlib

# ===========================================================
# GLOBAL SETTINGS
# ===========================================================
DEBUG_MODE = False
MAX_PREVIEW = 100

# ===========================================================
# Utility Functions
# ===========================================================
def debug(msg):
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}")

def safe_bytes_to_str(b):
    if b is None:
        return None
    if isinstance(b, str):
        return b
    for enc in ("utf-8", "latin-1", "utf-16"):
        try:
            return b.decode(enc)
        except:
            continue
    return None

def hex_snip(b, n=32):
    return binascii.hexlify(b[:n]).decode("ascii", errors="ignore")

def is_printable_text(s):
    if not isinstance(s, str) or len(s) == 0:
        return False
    good = sum(1 for c in s if c in string.printable)
    return good / len(s) > 0.7

def looks_like_zip(b):
    return isinstance(b, (bytes, bytearray)) and b.find(b'PK\x03\x04') != -1

def extract_zip_files(b):
    try:
        offset = b.find(b'PK\x03\x04')
        if offset == -1:
            return None
        zip_bytes = b[offset:]
        with io.BytesIO(zip_bytes) as bio:
            with zipfile.ZipFile(bio) as zf:
                return zf.namelist()
    except Exception as e:
        debug(f"ZIP extraction failed: {e}")
        return None

# ===========================================================
# Decoders
# ===========================================================
def decode_base64(s):
    try: return base64.b64decode(s, validate=False)
    except: return None

def decode_base32(s):
    try: return base64.b32decode(s, casefold=True)
    except: return None

def decode_base85(s):
    for f in (base64.b85decode, base64.a85decode):
        try: return f(s)
        except: continue
    return None

def decode_hex(s):
    try: return binascii.unhexlify("".join(s.split()))
    except: return None

def decode_url(s):
    try: return urllib.parse.unquote(s)
    except: return None

def decode_reverse(s):
    return s[::-1]

# ===========================================================
# Max-Resilience GZIP
# ===========================================================
def lenient_gunzip(data):
    debug("Attempting Max-Resilience GZIP/Deflate...")
    try: return gzip.decompress(data)
    except: pass
    try: return zlib.decompress(data, zlib.MAX_WBITS | 16)
    except: pass
    try:
        dobj = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
        output = dobj.decompress(data)
        output += dobj.flush()
        return output
    except Exception as e:
        debug(f"Stream Decompress failed: {e}")
        pass
    if len(data) >= 18:
        raw_stream = data[10:-8]
        try:
            return zlib.decompress(raw_stream, -zlib.MAX_WBITS)
        except: pass
    for i in range(1, 10):
        if len(data) > i:
            try:
                raw_stream_trimmed = data[i:-8]
                return zlib.decompress(raw_stream_trimmed, -zlib.MAX_WBITS)
            except: continue
    return None

# ===========================================================
# Standard Decoder List
# ===========================================================
STANDARD_DECODERS = [
    ("Base64", decode_base64),
    ("Base32", decode_base32),
    ("Base85", decode_base85),
    ("HEX", decode_hex),
    ("URL", decode_url),
    ("Reverse", decode_reverse),
]

# ===========================================================
# Smart Multi-pass Auto-Decode
# ===========================================================
def smart_auto_decode(input_data):
    results=[]
    candidates=[("Base64", decode_base64), ("Base32", decode_base32),
                ("Base85", decode_base85), ("HEX", decode_hex)]

    for name, func in candidates:
        decoded = func(input_data)
        if not decoded:
            continue

        # GZIP detection
        if isinstance(decoded, bytes) and decoded.startswith(b'\x1f\x8b'):
            debug(f"[{name}] Detected GZIP header.")
            decompressed = lenient_gunzip(decoded)
            if decompressed:
                txt = safe_bytes_to_str(decompressed)
                if txt:
                    results.append((f"{name} -> GZIP -> Text", txt[:MAX_PREVIEW]))
                    continue
                decoded = decompressed

        # ZIP detection
        if looks_like_zip(decoded):
            files = extract_zip_files(decoded)
            method = f"{name} -> ZIP"
            if decoded.startswith(b'\x1f\x8b'):
                method = f"{name} -> GZIP -> ZIP"
            if files:
                results.append((method, f"{len(decoded)} bytes, files: {', '.join(files)}"))
                continue
            else:
                results.append((f"{method} (binary)", f"{len(decoded)} bytes (hex start: {hex_snip(decoded)})"))
                continue

        # Text/Binary output
        txt = safe_bytes_to_str(decoded)
        if txt and is_printable_text(txt):
            results.append((f"{name} -> Text", txt[:MAX_PREVIEW]))
        else:
            results.append((f"{name} -> Binary", f"{len(decoded)} bytes (hex start: {hex_snip(decoded)})"))

    # URL decode
    if "%" in input_data:
        url_dec = decode_url(input_data)
        if url_dec != input_data:
            results.append(("URL Decode", url_dec[:MAX_PREVIEW]))

    return results
