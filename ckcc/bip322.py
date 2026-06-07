# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# bip322.py
#
# Build a single-input BIP-322 "message signing" PSBT for one key, ready to upload to a
# Coldcard for signing. Construction is adapted from the `bip322_txn` test fixture in
# ../afirmware/testing/bip322.py (single-input, non-taproot cases only).
#
import struct, hashlib

from .psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from .ctransaction import CTransaction, COutPoint, CTxIn, CTxOut
from .constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH


def bip322_msg_hash(msg):
    # BIP-322 tagged hash of the message (the "to_spend" commitment)
    tag_hash = hashlib.sha256(b'BIP0322-signed-message').digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def str_to_path(path):
    # Take string derivation path, and make a list of numbers (BIP-32 components).
    # - no syntax checking here
    rv = []
    for p in path.split('/'):
        if p == 'm': continue
        if not p: continue      # trailing or duplicated slashes

        if p[-1] in "'h":
            here = int(p[:-1]) | 0x80000000
        else:
            here = int(p)

        rv.append(here)

    return rv


def _script_pubkey(pubkey, addr_fmt):
    # Build scriptPubKey (and redeem_script, if any) for a single compressed pubkey.
    assert len(pubkey) == 33, "expect compressed pubkey"

    if addr_fmt == AF_CLASSIC:
        # p2pkh
        return bytes([0x76, 0xa9, 0x14]) + hash160(pubkey) + bytes([0x88, 0xac]), None

    if addr_fmt == AF_P2WPKH:
        # native segwit p2wpkh
        return bytes([0x00, 0x14]) + hash160(pubkey), None

    if addr_fmt == AF_P2WPKH_P2SH:
        # p2wpkh wrapped in p2sh
        redeem_script = bytes([0x00, 0x14]) + hash160(pubkey)
        scr = bytes([0xa9, 0x14]) + hash160(redeem_script) + bytes([0x87])
        return scr, redeem_script

    raise ValueError("unsupported addr_fmt for BIP-322: 0x%x" % addr_fmt)


def build_bip322_psbt(pubkey, msg, addr_fmt, master_fingerprint, subpath):
    # Construct a single-input BIP-322 PSBT (v0) for `pubkey` proving control of the
    # address derived from it, over the bytes `msg`.
    #
    #   pubkey            - 33-byte compressed public key (e.g. from decode_xpub)
    #   msg               - message to sign, as bytes
    #   addr_fmt          - one of AF_CLASSIC / AF_P2WPKH / AF_P2WPKH_P2SH
    #   master_fingerprint- device master key fingerprint, as int (dev.master_fingerprint)
    #   subpath           - full derivation path string for the key, e.g. "m/84h/0h/0h/0/0"
    if not isinstance(msg, bytes):
        msg = msg.encode('ascii')

    scr, redeem_script = _script_pubkey(pubkey, addr_fmt)

    # to_spend: virtual txn committing to the message; spent by the to_sign txn
    to_spend = CTransaction()
    to_spend.nVersion = 0
    to_spend.nLockTime = 0
    to_spend.vin = [CTxIn(COutPoint(hash=0, n=0xffffffff),
                          scriptSig=b'\x00\x20' + bip322_msg_hash(msg),
                          nSequence=0)]
    to_spend.vout = [CTxOut(0, scr)]
    to_spend.calc_sha256()

    # to_sign: spends to_spend's single output; this is what gets signed
    to_sign = CTransaction()
    to_sign.nVersion = 0
    to_sign.nLockTime = 0
    to_sign.vin = [CTxIn(COutPoint(to_spend.sha256, 0), nSequence=0)]
    to_sign.vout = [CTxOut(0, b'\x6a')]   # single zero-value OP_RETURN output

    path_ints = str_to_path(subpath)
    derivation = struct.pack('<I', master_fingerprint) \
                    + b''.join(struct.pack('<I', n) for n in path_ints)

    psbt = BasicPSBT()
    psbt.bip322_msg = msg
    psbt.inputs = [BasicPSBTInput(idx=0)]
    psbt.outputs = [BasicPSBTOutput(idx=0)]
    psbt.inputs[0].utxo = to_spend.serialize_with_witness()
    psbt.inputs[0].bip32_paths[pubkey] = derivation
    if redeem_script is not None:
        psbt.inputs[0].redeem_script = redeem_script
    psbt.txn = to_sign.serialize_with_witness()

    return psbt.as_bytes()

# EOF
