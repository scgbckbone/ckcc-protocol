import pytest, pyaes
from hashlib import sha256
from hmac import HMAC
from struct import pack
from ckcc.constants import AF_P2WPKH, USB_NCRY_V1, USB_NCRY_V2, USB_NCRY_V3, USB_V3_C2D, USB_V3_D2C
from ckcc.client import ColdcardDevice, CCProtocolPacker, usb_v3_keys
from ckcc.protocol import CCFramingError


def xor_bytes(left, right):
    assert len(left) == len(right)
    return bytes(a ^ b for a, b in zip(left, right))


# v2 tests require you to have firmware supporting usb encryption v2
# after each v2 test, coldcard needs to be reconnected


def test_ncry_v1():
    # USB_NCRY_V1 is the default
    dev = ColdcardDevice()
    session_key = dev.session_key
    assert session_key
    # re-establish shared secret
    dev.start_encryption()
    assert dev.ncry_ver == USB_NCRY_V1
    assert session_key != dev.session_key
    session_key = dev.session_key
    # we can do this many times over - it will always work
    dev.start_encryption()
    assert dev.ncry_ver == USB_NCRY_V1
    assert session_key != dev.session_key


def test_ncry_v2():
    # after this test, one needs to reconnect coldcard
    dev = ColdcardDevice(ncry_ver=USB_NCRY_V2)
    assert dev.session_key
    assert dev.ncry_ver == USB_NCRY_V2
    # cannot start new session - already bound
    with pytest.raises(Exception):
        dev.start_encryption()
    # cannot start new session even with v2 - already bound
    with pytest.raises(Exception):
        dev.start_encryption(version=USB_NCRY_V2)
    # if above conditions are met - all commands gonna be encrypted
    assert dev.ncry_ver == USB_NCRY_V2
    addr = dev.send_recv(CCProtocolPacker.show_address("m/84'/0'/0'/0/0", AF_P2WPKH), timeout=None)
    assert addr


def test_ncry_v2_via_start_encryption():
    dev = ColdcardDevice()
    assert dev.session_key
    assert dev.ncry_ver == USB_NCRY_V1
    dev.start_encryption(version=USB_NCRY_V2)
    assert dev.ncry_ver == USB_NCRY_V2
    # cannot start new session - already bound
    with pytest.raises(Exception):
        dev.start_encryption()
    # cannot start new session even with v2 - already bound
    with pytest.raises(Exception):
        dev.start_encryption(version=USB_NCRY_V2)
    # test some commands
    assert dev.ncry_ver == USB_NCRY_V2
    assert dev.encrypt_request is not None
    # if above conditions are met - all commands gonna be encrypted
    addr = dev.send_recv(CCProtocolPacker.show_address("m/84'/0'/0'/0/0", AF_P2WPKH), timeout=None)
    assert addr


def test_unsupported_version():
    dev = ColdcardDevice()
    with pytest.raises(ValueError):
        dev.start_encryption(version=0x4)
    dev.close()
    with pytest.raises(ValueError):
        ColdcardDevice(ncry_ver=0x4)


def test_ncry_v3_packer():
    pubkey = bytes(range(64))
    msg = CCProtocolPacker.encrypt_start(pubkey, version=USB_NCRY_V3)

    assert msg[:4] == b'ncry'
    assert msg[4:8] == pack('<I', USB_NCRY_V3)
    assert msg[8:] == pubkey


def test_ncry_v3_directional_keys_and_request_mac():
    session_key = sha256(b'ncry-v3-session').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    h2d_enc, h2d_mac, d2h_enc, d2h_mac = usb_v3_keys(
        session_key, host_pubkey, dev_pubkey)
    assert h2d_enc != d2h_enc
    assert h2d_mac != d2h_mac

    wire = dev.encrypt_request(b'pinghello')
    ciphertext, tag = wire[:-32], wire[-32:]
    expect_tag = HMAC(
        h2d_mac,
        pack('<4sII', USB_V3_C2D, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()

    assert tag == expect_tag
    assert dev.tx_seq == 1


def test_ncry_v3_directional_streams_cannot_be_xored_to_decrypt():
    session_key = sha256(b'ncry-v3-stream-xor').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))
    host_plaintext = b'host request plaintext'
    device_plaintext = b'device reply plaintext'

    h2d_enc, _, d2h_enc, _ = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    host_ciphertext = pyaes.AESModeOfOperationCTR(
        h2d_enc, pyaes.Counter(0)).encrypt(host_plaintext)
    device_ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(device_plaintext)

    # With reused CTR keystreams, C1 xor C2 equals P1 xor P2, and knowing
    # one plaintext lets an observer recover the other. V3 direction keys
    # must break that relationship.
    assert xor_bytes(host_ciphertext, device_ciphertext) != xor_bytes(
        host_plaintext, device_plaintext)
    recovered_device_plaintext = xor_bytes(
        device_ciphertext, xor_bytes(host_ciphertext, host_plaintext))
    assert recovered_device_plaintext != device_plaintext


def test_ncry_v3_response_auth_and_replay_rejection():
    session_key = sha256(b'ncry-v3-response').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    plaintext = b'ascihello'
    ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(plaintext)
    tag = HMAC(
        d2h_mac,
        pack('<4sII', USB_V3_D2C, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()
    wire = ciphertext + tag

    assert dev.decrypt_response(wire) == plaintext
    assert dev.rx_seq == 1

    with pytest.raises(CCFramingError):
        dev.decrypt_response(wire)


def test_ncry_v3_response_tamper_rejected_before_sequence_increment():
    session_key = sha256(b'ncry-v3-tamper').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    plaintext = b'ascihello'
    ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(plaintext)
    tag = HMAC(
        d2h_mac,
        pack('<4sII', USB_V3_D2C, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()
    wire = bytearray(ciphertext + tag)
    wire[0] ^= 1

    with pytest.raises(CCFramingError):
        dev.decrypt_response(bytes(wire))
    assert dev.rx_seq == 0
