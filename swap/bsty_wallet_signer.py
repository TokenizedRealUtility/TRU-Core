#!/usr/bin/env python3
"""
BSTY wallet signer helper for TRU-SWAP-B.

The coordinator sends only:
- wallet address
- expected compressed pubkey
- 32-byte sighash

Legacy wallets:
- obtain the WIF locally with dumpprivkey.

Descriptor wallets:
- obtain private descriptors locally with listdescriptors true,
- scan wallet-private extended keys without depending on descriptor text shape,
- derive only candidates along the already-bound wallet hdkeypath in this short-lived helper process.

In both modes, the helper verifies the derived key maps to the expected pubkey,
signs the supplied digest, returns DER+SIGHASH_ALL, and exits. Private key,
WIF, xprv, and private descriptor material are never returned to the
coordinator or written to disk.
"""

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HARD = 0x80000000


def fail(msg):
    raise RuntimeError(msg)


def rpc(cli, wallet, method, *args):
    return subprocess.run(
        [cli, f"-rpcwallet={wallet}", method, *map(str, args)],
        text=True, capture_output=True
    )


def rpc_json(cli, wallet, method, *args, private=False):
    cp = rpc(cli, wallet, method, *args)
    if cp.returncode != 0:
        if private:
            fail(f"{method} failed; private descriptor material unavailable or wallet locked")
        detail = (cp.stderr or cp.stdout).strip().replace("\n", " | ")[:500]
        fail(f"{method} failed" + (f": {detail}" if detail else ""))
    try:
        return json.loads(cp.stdout)
    except Exception:
        fail(f"{method} returned invalid JSON")


def b58decode(s):
    n = 0
    for ch in s:
        if ch not in B58:
            fail("invalid base58 character")
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def b58check_payload(s):
    raw = b58decode(s.strip())
    if len(raw) < 5:
        fail("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != want:
        fail("base58check checksum mismatch")
    return payload


def decode_wif(wif):
    payload = b58check_payload(wif)
    if len(payload) == 34 and payload[-1] == 1:
        priv = payload[1:33]
        compressed = True
    elif len(payload) == 33:
        priv = payload[1:33]
        compressed = False
    else:
        fail("unsupported WIF payload length")
    k = int.from_bytes(priv, "big")
    if not (1 <= k < N):
        fail("invalid private scalar")
    if not compressed:
        fail("TRU-SWAP-B requires compressed BSTY wallet keys")
    return k


def decode_xprv(xprv):
    payload = b58check_payload(xprv)
    if len(payload) != 78:
        fail("extended private key payload must be 78 bytes")
    depth = payload[4]
    chain = payload[13:45]
    keydata = payload[45:78]
    if len(keydata) != 33 or keydata[0] != 0:
        fail("descriptor does not contain an extended private key")
    k = int.from_bytes(keydata[1:], "big")
    if not (1 <= k < N):
        fail("invalid extended private scalar")
    return depth, chain, k


def inv(a, m):
    return pow(a, -1, m)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * inv(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def mul(k, pt=G):
    out = None
    add = pt
    while k:
        if k & 1:
            out = point_add(out, add)
        add = point_add(add, add)
        k >>= 1
    return out


def compressed_pubkey(k):
    x, y = mul(k)
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def ckd_priv(k, chain, child):
    if not (0 <= child <= 0xFFFFFFFF):
        fail("BIP32 child index out of range")
    if child & HARD:
        data = b"\x00" + k.to_bytes(32, "big")
    else:
        data = compressed_pubkey(k)
    data += child.to_bytes(4, "big")
    i64 = hmac.new(chain, data, hashlib.sha512).digest()
    il = int.from_bytes(i64[:32], "big")
    if il >= N:
        fail("invalid BIP32 derivation IL")
    child_k = (il + k) % N
    if child_k == 0:
        fail("invalid zero BIP32 child key")
    return child_k, i64[32:]


def parse_component(text):
    s = text.strip()
    if not s:
        fail("empty BIP32 path component")
    hardened = s[-1:] in ("'", "h", "H")
    if hardened:
        s = s[:-1]
    if not s.isdigit():
        fail("invalid BIP32 path component")
    n = int(s)
    if n >= HARD:
        fail("BIP32 path component too large")
    return n | (HARD if hardened else 0)


def parse_path(path):
    p = path.strip()
    if p == "m":
        return []
    if not p.startswith("m/"):
        fail("wallet hdkeypath is not absolute")
    return [parse_component(x) for x in p[2:].split("/")]


def parse_origin_path(text):
    t = text.strip()
    if not t:
        return []
    if t.startswith("/"):
        t = t[1:]
    return [] if not t else [parse_component(x) for x in t.split("/")]


def parse_suffix_template(text):
    t = text.strip()
    if not t:
        return []
    if t.startswith("/"):
        t = t[1:]
    out = []
    for x in ([] if not t else t.split("/")):
        if x == "*":
            out.append(("wild", None))
        elif x in ("*'", "*h", "*H"):
            out.append(("hard_wild", None))
        elif x.startswith("<") and x.endswith(">"):
            alts = x[1:-1].split(";")
            if not alts or any(not a for a in alts):
                fail("invalid descriptor multipath component")
            out.append(("alts", tuple(parse_component(a) for a in alts)))
        else:
            out.append(("fixed", parse_component(x)))
    return out


def descriptor_key_parts(desc):
    body = desc.split("#", 1)[0]
    # GROUP-05 BSTY role addresses are single-key wpkh descriptors.
    m = re.fullmatch(
        r"wpkh\(\[([0-9a-fA-F]{8})([^\]]*)\]([1-9A-HJ-NP-Za-km-z]+)([^)]*)\)",
        body,
    )
    if not m:
        return None
    return {
        "fingerprint": m.group(1).lower(),
        "origin": parse_origin_path(m.group(2)),
        "xkey": m.group(3),
        "suffix": parse_suffix_template(m.group(4)),
    }


def suffix_matches(template, rest):
    if len(template) != len(rest):
        return False
    for item, got in zip(template, rest):
        kind, val = item
        if kind == "wild":
            if got & HARD:
                return False
        elif kind == "hard_wild":
            if not (got & HARD):
                return False
        elif kind == "alts":
            if got not in val:
                return False
        elif kind == "fixed":
            if val != got:
                return False
        else:
            return False
    return True

def private_extended_keys(desc):
    """Return private extended keys found in a descriptor, without exposing them.

    GlobalBoost descriptor serialization is allowed to vary. The exact bound
    role pubkey is the authority, not the textual descriptor shape.
    """
    body = str(desc).split("#", 1)[0]
    found = []
    seen = set()
    # Extended keys are Base58Check strings around 111 chars. Scan broadly,
    # then accept only payloads that decode as a 78-byte private extended key.
    for token in re.findall(r"[1-9A-HJ-NP-Za-km-z]{80,120}", body):
        if token in seen:
            continue
        try:
            depth, chain, k = decode_xprv(token)
        except Exception:
            continue
        seen.add(token)
        found.append((depth, chain, k))
    return found


def derive_descriptor_key(cli, wallet, address, expected):
    ai = rpc_json(cli, wallet, "getaddressinfo", address)
    if ai.get("ismine") is not True or ai.get("solvable") is not True:
        fail("BSTY signer address is not an owned solvable wallet address")
    got_pub = str(ai.get("pubkey", "")).lower()
    if got_pub != expected.hex():
        fail("BSTY signer address pubkey does not match expected HTLC role pubkey")
    if str(ai.get("desc", "")).split("(", 1)[0] != "wpkh":
        fail("descriptor signer currently requires a wpkh role address")

    full_path = parse_path(str(ai.get("hdkeypath", "")))
    fp = str(ai.get("hdmasterfingerprint", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{8}", fp):
        fail("BSTY signer address lacks a valid master fingerprint")

    listing = rpc_json(cli, wallet, "listdescriptors", "true", private=True)
    descs = listing.get("descriptors") if isinstance(listing, dict) else None
    if not isinstance(descs, list):
        fail("listdescriptors true returned no descriptor array")

    # Do not trust a particular descriptor text shape. Wallet implementations
    # can serialize the same seed/account key with different origin/multipath
    # syntax. Instead, inspect only private extended keys returned by THIS
    # wallet and try each possible ancestor position along the already-bound
    # public hdkeypath. The final compressed pubkey must equal `expected`.
    #
    # For m/84'/0'/0'/0/22 there are only six possible ancestor cuts:
    #   master, 84', 0', 0', 0, or exact child.
    # This is bounded and deterministic.
    private_xkeys = []
    seen_xkeys = set()
    for item in descs:
        if not isinstance(item, dict):
            continue
        d = str(item.get("desc", ""))
        # If an origin fingerprint is explicitly present and different from
        # the role's master fingerprint, skip it. Origin-less descriptors are
        # still allowed because the exact resulting pubkey remains mandatory.
        origins = re.findall(r"\[([0-9a-fA-F]{8})(?:[^\]]*)\]", d)
        if origins and fp not in {x.lower() for x in origins}:
            continue
        for depth, chain, k in private_extended_keys(d):
            ident = (depth, chain, k)
            if ident not in seen_xkeys:
                seen_xkeys.add(ident)
                private_xkeys.append(ident)

    matches = []
    attempts = 0
    for _depth, chain0, k0 in private_xkeys:
        # Try every suffix of the known absolute path. This handles xprvs
        # serialized at master, account, branch, or exact-child depth without
        # relying on descriptor formatting or the advisory extended-key depth.
        for cut in range(len(full_path) + 1):
            attempts += 1
            k, chain = k0, chain0
            try:
                for child in full_path[cut:]:
                    k, chain = ckd_priv(k, chain, child)
                if compressed_pubkey(k) == expected:
                    matches.append(k)
            except Exception:
                continue

    # Drop private descriptor references before signing/output.
    listing = None
    descs = None
    private_xkeys = None

    unique = set(matches)
    if len(unique) != 1:
        fail(
            "descriptor role-key resolution failed "
            f"(private_xkeys={len(seen_xkeys)}, derivation_attempts={attempts}, "
            f"pubkey_matches={len(matches)}, unique_keys={len(unique)})"
        )
    return next(iter(unique))

def rfc6979_k(priv, z):
    x = priv.to_bytes(32, "big")
    h1 = (z % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def der_int(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign(priv, digest):
    z = int.from_bytes(digest, "big")
    k = rfc6979_k(priv, z)
    x, _ = mul(k)
    r = x % N
    s = (inv(k, N) * (z + r * priv)) % N
    if s > N // 2:
        s = N - s
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", required=True)
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--digest", required=True)
    args = ap.parse_args()

    digest = bytes.fromhex(args.digest)
    if len(digest) != 32:
        fail("digest must be 32 bytes")
    expected = bytes.fromhex(args.pubkey)
    if len(expected) != 33 or expected[0] not in (2, 3):
        fail("expected pubkey must be compressed")

    wi = rpc_json(args.cli, args.wallet, "getwalletinfo")
    if wi.get("private_keys_enabled") is False:
        fail("BSTY wallet has private keys disabled")

    if wi.get("descriptors") is True:
        priv = derive_descriptor_key(
            args.cli, args.wallet, args.address, expected
        )
        mode = "descriptor"
    else:
        cp = rpc(args.cli, args.wallet, "dumpprivkey", args.address)
        if cp.returncode != 0:
            fail("dumpprivkey failed; wallet may be locked or address may not belong to this wallet")
        wif = cp.stdout.strip()
        priv = decode_wif(wif)
        wif = None
        got = compressed_pubkey(priv)
        if got != expected:
            fail("wallet address private key does not match expected HTLC role pubkey")
        mode = "legacy"

    if compressed_pubkey(priv) != expected:
        fail("derived BSTY private key does not match expected HTLC role pubkey")

    sig = sign(priv, digest) + b"\x01"
    priv = None
    print(json.dumps({
        "signatureHex": sig.hex(),
        "sighash": "ALL",
        "signerMode": mode,
        "privateMaterialReturned": False,
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print("ERROR:", str(e), file=sys.stderr)
        raise SystemExit(1)
