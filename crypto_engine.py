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

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    if len(b1) != len(b2):
        raise ValueError(f"A két bájtsorozat hossza nem egyezik! ({len(b1)} vs {len(b2)} bájt)")
    return bytes([x ^ y for x, y in zip(b1, b2)])
def encrypt_by_mode(params: dict, P: list[bytes]) -> list[bytes]:
    C=[]
    match params["mode"]:
        case "ECB":
            for i in P:
                C.append(encrypt(i, params['cipher'], params['key']))
        case "CBC": #ugyanolyan hosszuk kell legyenek IV és a blockok
            C.append(params["IV"])
            for i in range(len(P)):
                C.append(encrypt(xor_bytes(P(i), C(i)), params['cipher'], params['key']))
            #C.pop(0)
        case "CFB":
            C.append(params["IV"])
            for i in range(len(P)):
                C.append(xor_bytes(P(i), encrypt(C(i), params['cipher'], params['key'])))
            #C.pop(0)
        case "OFB":
            O=params["IV"]
            for i in P:
                O=encrypt(O, params['cipher'], params['key'])
                C.append(xor_bytes(O, i))
        case "CTR":
            ...
        case _:
            raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")
    return C


def decrypt_by_mode(params: dict, C: list[bytes]) -> list[bytes]:
    P=[]
    match params["mode"]:
        case "ECB":
            for i in C:
                P.append(decrypt(i, params['cipher'], params['key']))
        case "CBC":
            P.append(xor_bytes(params("IV"), decrypt(C[0],params['cipher'], params['key'])))
            for i in range(1, len(C)):
                P.append(xor_bytes(C[i-1], decrypt(C[i],params['cipher'], params['key'])))
        case "CFB":
            C.insert(0, params["IV"])
            for i in range(1, len(C)):
                P.append(xor_bytes(C[i], encrypt(C[i-1], params['cipher'], params['key'])))
            C.pop(0) #nem akarom módosítani a decriptálandó tömböt
        case "OFB":
            O=params["IV"]
            for i in C:
                O=encrypt(O, params['cipher'], params['key'])
                P.append(xor_bytes(O, i))
        case "CTR":
            ...
        case _:
                    raise ValueError(f"Ismeretlen működési mód: {params["mode"]}")
    return P
        
    

            
    