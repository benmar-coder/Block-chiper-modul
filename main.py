import config
from crypto_engine import*
from inout import read_input_file
from inout import write_output_file


from config import load_cipher_config

def main():
    try:
        params = load_cipher_config('config.json', 'schema.json')
    
        print("Sikeres beolvasás és validáció!")
        print(f"Algoritmus: {params['cipher']}")
        print(f"Mód: {params['mode']}")
        print(f"Blokkméret: {params['blocksize']} bájt")
        print(f"Kulcs hossza: {len(params['key'])} bájt")
        if params['iv']:
            print(f"IV hossza: {len(params['iv'])} bájt")

    except ValueError as hiba:
        print(f"HIBA: {hiba}")

    try:
        print(f"Fájl beolvasása:...")
        input = read_input_file('be.bin')
        write_output_file('ki.bin', input)
    except Exception as e:
        print(f"Fájlolvasási hiba: {e}")
        return

    blocks=data_to_blocks(input)

    




