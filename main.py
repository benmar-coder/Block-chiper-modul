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

    try:
        print(f"Fájl beolvasása:...")
        input = read_input_file('be.bin')
    except Exception as e:
        print(f"Fájlolvasási hiba: {e}")
        return

    print("Sikeres beolvasás")
    encrypting=True

    if encrypting:
        input=add_padding(input, params['blocksize'], params['padding'])
        print("Padding hozzáadva")
        
        blocks=data_to_blocks(input, params['blocksize'])
        print("Szöveg blokkokra bontva:")
        print(blocks)

        enc_blocks=encrypt_by_mode(params, blocks)
        print("A blokkokat titkosítva:")
        print(enc_blocks)

        output=blocks_to_data(enc_blocks)
        print("A blokkok összefűzése megtörtént")
        print(output)

        write_output_file('ki.bin', output)
        print("A kiíratás megtörtént")
    else:
        #valszeg ez nem kell
        input=add_padding(input, params['blocksize'], params['padding'])
        print("Padding hozzáadva")

        blocks=data_to_blocks(input, params['blocksize'])
        print("Szöveg blokkokra bontva:")
        print(blocks)
        
        enc_blocks=decrypt_by_mode(params, blocks)
        print("A blokkokat titkosítva:")
        print(enc_blocks)

        output=blocks_to_data(enc_blocks)
        print("A blokkok összefűzése megtörtént")
        print(output)

        write_output_file('ki.bin', output)
        print("A kiíratás megtörtént")

main()

    




