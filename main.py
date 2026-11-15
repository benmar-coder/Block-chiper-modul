from config import *
from crypto_engine import *
from inout import *


def main():
    try:
        params = load_cipher_config('config.json', 'schema.json')
    
        print("Sikeres beolvasás és validáció!")
        print(f"Algoritmus: {params['cipher']}")
        print(f"Mód: {params['mode']}")
        print(f"Blokkméret: {params['blocksize']} bájt")
        print(f"Kulcs hossza: {len(params['key'])} bájt")
        print(params['key'])
        if params['iv']:
            print(f"IV hossza: {len(params['iv'])} bájt")

    except ValueError as hiba:
        print(f"HIBA: {hiba}")
        return

    try:
        print(f"Fájl beolvasása:...")
        input = read_input_file('be.bin')
    except Exception as e:
        print(f"Fájlolvasási hiba: {e}")
        return

    print("Sikeres beolvasás")
    encrypting=True
    output=main_enc_dec(params, encrypting, input)
    write_output_file('ki.bin', output)
    print("A kiíratás megtörtént")

def main_enc_dec(params: dict, encrypting: bool, input: bytes) ->bytes:

    enc_fn, dec_fn = get_cipher_functions(params['cipher'])
    if encrypting:
        input=add_padding(input, params['blocksize'], params['padding'])
        print("Padding hozzáadva")
        
        blocks=data_to_blocks(input, params['blocksize'])
        print("Szöveg blokkokra bontva:")
        #print(blocks)

        enc_blocks=encrypt_by_mode(params, blocks, enc_fn)
        print("A blokkokat titkosítva:")
        #print(enc_blocks)

        output=blocks_to_data(enc_blocks)
        print("A blokkok összefűzése megtörtént")
    else:

        blocks=data_to_blocks(input, params['blocksize'])
        print("Szöveg blokkokra bontva:")
        #print(blocks)

        
        enc_blocks=decrypt_by_mode(params, blocks, enc_fn, dec_fn)
        print("A blokkokat titkosítva:")
        #print(enc_blocks)

        output=blocks_to_data(enc_blocks)

        output=remove_padding(output, params['blocksize'], params['padding'])
        print("A blokkok összefűzése megtörtént")
        #print(output)
    return output

if __name__ == "__main__":
    main()

    




