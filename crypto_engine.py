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

def encrypt_block(block: bytes, mode: str, key: bytes) -> bytes:
    enc_block=bytearray();
    match mode:
        case 'VIGENERE-BIN':
            for i in range(len(block)):
                enc_block.append(block[i]^key[i%len(key)])
            return bytes(enc_block)
        case 'DES':
            ...
        case _:
            raise ValueError(f"Ismeretlen encrypt mód: {mode}")

def decrypt_block(block: bytes, mode: str, key: bytes) -> bytes:
    dec_block=bytearray();
    match mode:
        case 'VIGENERE-BIN':
            for i in range(len(block)):
                dec_block.append(block[i]^key[i%len(key)])
            return bytes(dec_block)
        case 'DES':
            ...
        case _:
            raise ValueError(f"Ismeretlen encrypt mód: {mode}")

def data_to_blocks(data: bytes, blocksize:int):
    blocks=[]
    ind=0;
    while ind<len(data):
        blocks.append(data[ind:(ind+blocksize)])
        ind+=blocksize;
    return blocks
    

            
    