from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def add_padding(input_bytes: bytes, blocksize: int, mode: str) -> bytes:
    pad_len = blocksize - (len(input_bytes) % blocksize)

    if pad_len == blocksize:
        return input_bytes
    
    match mode:
        case 'ZERO':
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

def encrypt(block: bytes, mode: str, key: bytes) -> bytes:
    match mode:
        case 'VIGENERE-BIN':
            for i in range(len(block)):
                enc_block=bytearray();
                enc_block.append(block[i]^key[i%len(key)])
            return bytes(enc_block)
        case 'AES-128':
            if len(key) != 16:
                raise ValueError(f"A AES-128 kulcs hossza pontosan 16 bájt kell legyen, de {len(key)} bájtot kaptam!")
            if len(block) != 16:
                raise ValueError(f"A AES-128 blokk hossza pontosan 16 bájt kell legyen, de {len(block)} bájtot kaptam!")
            cipher = Cipher(algorithms.AES128(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            return encryptor.update(block) + encryptor.finalize()
        case _:
            raise ValueError(f"Ismeretlen encrypt mód: {mode}")

def decrypt(block: bytes, mode: str, key: bytes) -> bytes:
    dec_block=bytearray();
    match mode:
        case 'VIGENERE-BIN':
            for i in range(len(block)):
                dec_block.append(block[i]^key[i%len(key)])
            return bytes(dec_block)
        case 'AES-128':
                if len(key) != 16:
                    raise ValueError(f"A AES-128 kulcs hossza pontosan 16 bájt kell legyen, de {len(key)} bájtot kaptam!")
                if len(block) != 16:
                    raise ValueError(f"A AES-128 blokk hossza pontosan 16 bájt kell legyen, de {len(block)} bájtot kaptam!")
                cipher = Cipher(algorithms.AES128(key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                return decryptor.update(block) + decryptor.finalize()
        case _:
            raise ValueError(f"Ismeretlen decrypt mód: {mode}")

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


def encrypt_by_mode(params: dict, P: list[bytes]) -> list[bytes]:
    C=[]
    match params["mode"]:
        case "ECB":
            for i in P:
                C.append(encrypt(i, params['cipher'], params['key']))
            return C
        case "CBC":
            ...
        case "CFB":
            ...
        case "OFB":
            ...
        case "CTR":
            ...
        case _:
            raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")


def decrypt_by_mode(params: dict, C: list[bytes]) -> list[bytes]:
    P=[]
    match params["mode"]:
        case "ECB":
            for i in C:
                P.append(decrypt(i, params['cipher'], params['key']))
            return P
        case "CBC":
            ...
        case "CFB":
            ...
        case "OFB":
            ...
        case "CTR":
            ...
        case _:
                    raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")
        
    

            
    