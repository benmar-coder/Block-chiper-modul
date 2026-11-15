import os
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from main import main_enc_dec

#Véletlen bemenet
@pytest.fixture(scope="module")
def data_1mb():
    return os.urandom(1024 * 1024)

#Dekódolás, kódolás
@pytest.mark.parametrize("cipher_algo", ["AES-128", "VIGENERE-BIN"])
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CFB", "OFB"]) #CTR majd kell
def test_encryption_decryption_roundtrip(data_1mb, cipher_algo, mode):
    config = {
        "blocksize": 16,
        "cipher": cipher_algo,
        "mode": mode,
        "padding": "SF",
        "key": b'12345678',
        "iv": b'87654321'
    }

    encrypted = main_enc_dec(config, True, data_1mb)
    
    decrypted = main_enc_dec(config, False, encrypted)
    
    assert decrypted == data_1mb

# AES128 teszt
@pytest.mark.parametrize("mode_name", ["ECB", "CBC", "CFB", "OFB"])
def test_against_standard_library(data_1mb, mode_name):
    key = b'12345678'
    iv = b'87654321'
    
    test_data = data_1mb[:1024] # Hogy gyorsabb legyen, csak 1KB-t nézünk
    
    if mode_name == "ECB":
        cipher = Cipher(algorithms.AES128(key), modes.ECB(), backend=default_backend())
    elif mode_name == "CBC":
        cipher = Cipher(algorithms.AES128(key), modes.CBC(iv), backend=default_backend())
    elif mode_name == "CFB":
        cipher = Cipher(algorithms.AES128(key), modes.CFB(iv), backend=default_backend())
    elif mode_name == "OFB":
        cipher = Cipher(algorithms.AES128(key), modes.OFB(iv), backend=default_backend())
    
    encryptor = cipher.encryptor()
    official_encrypted = encryptor.update(test_data) + encryptor.finalize()

    config = {"blocksize": 16, "cipher": "AES128", "mode": mode_name, "padding": "ZERO", "key": key, "iv": iv}
    my_encrypted = main_enc_dec(config, True, data_1mb)
    
    assert my_encrypted == official_encrypted