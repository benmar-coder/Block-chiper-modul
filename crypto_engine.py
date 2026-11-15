from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Callable

def add_padding(input_bytes: bytes, blocksize: int, mode: str) -> bytes:
    pad_len = blocksize - (len(input_bytes) % blocksize)

    
    
    match mode:
        case 'ZERO':
            if pad_len == blocksize:
                return input_bytes
            return input_bytes + (b'\x00' * pad_len)
            
        case 'DES':
            # 1 bit (0x80) + a többi nulla bit
            padding = b'\x80' + (b'\x00' * (pad_len - 1))
            return input_bytes + padding
            
        case 'SF':
            padding = bytes([pad_len] * pad_len)
            return input_bytes + padding
            
        case _:
            raise ValueError(f"Ismeretlen padding mód: {mode}")


def remove_padding(padded_bytes: bytes, blocksize: int, padding_mode: str) -> bytes:
    if not padded_bytes:
        return padded_bytes

    match padding_mode:
        case 'ZERO':
            return padded_bytes.rstrip(b'\x00')
            
        case 'DES':
            i = len(padded_bytes) - 1
            while i >= 0 and padded_bytes[i] == 0x00:
                i -= 1
            if i < 0 or padded_bytes[i] != 0x80:
                raise ValueError("Érvénytelen DES padding!")
            return padded_bytes[:i]
            
        case 'SF':
            pad_len = padded_bytes[-1]
            if pad_len < 1 or pad_len > blocksize:
                raise ValueError(f"Érvénytelen SF padding hossz: {pad_len}")
            if padded_bytes[-pad_len:] != bytes([pad_len] * pad_len):
                raise ValueError("Sérült SF padding bájtok!")
            return padded_bytes[:-pad_len]

        case _:
                    raise ValueError(f"Ismeretlen padding mód: {mode}")

def vigenere_bin_encrypt_block(block: bytes, key: bytes) -> bytes:
    return bytes([(block[i] + key[i % len(key)]) % 256 for i in range(len(block))])

def vigenere_bin_decrypt_block(block: bytes, key: bytes) -> bytes:
    return bytes([(block[i] - key[i % len(key)]) % 256 for i in range(len(block))])

def aes128_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 esetén a blokk és a kulcs hossza 16 bájt kell legyen!")
    cipher = Cipher(algorithms.AES128(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def aes128_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 esetén a blokk és a kulcs hossza 16 bájt kell legyen!")
    cipher = Cipher(algorithms.AES128(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()

def get_cipher_functions(cipher_name: str) -> tuple[Callable[[bytes, bytes], bytes], Callable[[bytes, bytes], bytes]]:
    match cipher_name:
        case 'VIGENERE-BIN':
            return vigenere_bin_encrypt_block, vigenere_bin_decrypt_block
        case 'AES-128':
            return aes128_encrypt_block, aes128_decrypt_block
        case _:
            raise ValueError(f"Nem támogatott algoritmus: {cipher_name}")

def data_to_blocks(data: bytes, blocksize:int) -> list[bytes]:
    blocks=[]
    ind=0;
    while ind<len(data):
        blocks.append(data[ind:(ind+blocksize)])
        ind+=blocksize;
    return blocks

def blocks_to_data(blocks: list[bytes]) -> bytes:
    data=bytes();
    for i in blocks:
        data+=i
    return data

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    if len(b1) != len(b2):
        raise ValueError(f"A két bájtsorozat hossza nem egyezik! ({len(b1)} vs {len(b2)} bájt)")
    return bytes([x ^ y for x, y in zip(b1, b2)])

def increment_counter(iv: bytes, increment: int) -> bytes:
    """CTR módhoz növeli a számláló (IV) értékét."""
    blocksize = len(iv)
    val = int.from_bytes(iv, byteorder='big')
    new_val = (val + increment) % (1 << (blocksize * 8))
    return new_val.to_bytes(blocksize, byteorder='big')

def encrypt_by_mode(params: dict, P: list[bytes], encrypt_fn: Callable[[bytes, bytes], bytes]) -> list[bytes]:
    C=[]
    match params["mode"]:
        case "ECB":
            for i in P:
                C.append(encrypt_fn(i, params['key']))
        case "CBC": #ugyanolyan hosszuk kell legyenek IV és a blockok
            C.append(params["iv"])
            for i in range(len(P)):
                C.append(encrypt_fn(xor_bytes(P[i], C[i]), params['key']))
            C.pop(0)
        case "CFB":
            C.append(params["iv"])
            for i in range(len(P)):
                C.append(xor_bytes(P[i], encrypt_fn(C[i], params['key'])))
            C.pop(0)
        case "OFB":
            O=params["iv"]
            for i in P:
                O=encrypt_fn(O, params['key'])
                C.append(xor_bytes(O, i))
        case "CTR":
            for i, block in enumerate(P):
                counter_block = increment_counter(params['iv'], i)
                keystream = encrypt_fn(counter_block, params['key'])
                C.append(xor_bytes(block, keystream))
        case _:
            raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")
    return C


def decrypt_by_mode(params: dict, C: list[bytes], encrypt_fn: Callable[[bytes, bytes], bytes], decrypt_fn: Callable[[bytes, bytes], bytes],) -> list[bytes]:
    P=[]
    match params["mode"]:
        case "ECB":
            for i in C:
                P.append(decrypt_fn(i, params['key']))
        case "CBC":
            P.append(xor_bytes(params("iv"), decrypt_fn(C[0], params['key'])))
            for i in range(1, len(C)):
                P.append(xor_bytes(C[i-1], decrypt_fn(C[i], params['key'])))
        case "CFB":
            C.insert(0, params["iv"])
            for i in range(1, len(C)):
                P.append(xor_bytes(C[i], encrypt_fn(C[i-1], params['key'])))
            C.pop(0) #nem akarom módosítani a decriptálandó tömböt
        case "OFB":
            O=params["iv"]
            for i in C:
                O=encrypt_fn(O, params['key'])
                P.append(xor_bytes(O, i))
        case "CTR":
            for i, block in enumerate(C):
                counter_block = increment_counter(params["iv"], i)
                keystream = encrypt_fn(counter_block, params["key"])
                P.append(xor_bytes(block, keystream))
        case _:
                    raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")
    return P
        
    

            
    