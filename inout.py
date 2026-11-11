import os

def read_input_file(filepath: str) -> bytes:
    """
    Beolvassa a megadott fájlt bináris módban, és visszaadja a tartalmát bájtokként.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Hiba: A '{filepath}' fájl nem található!")

    try:
        # Az 'rb' (read binary) mód a legfontosabb! 
        # Ez garantálja, hogy a fájl tartalma bytes típusú lesz, nem pedig string.
        with open(filepath, 'rb') as f:
            data = f.read()
        return data
    except Exception as e:
        raise IOError(f"Kritikus hiba a '{filepath}' beolvasása közben: {e}")

def write_output_file(filepath: str, data: bytes) -> None:
    """
    Kiírja a megadott bájtokat (titkosított vagy dekódolt adatot) egy fájlba.
    """
    try:
        # A 'wb' (write binary) mód bájtokat ír a fájlba.
        # Figyelem: ha a fájl már létezik, ez felülírja a tartalmát!
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"Sikeresen kiírva {len(data)} bájt ide: '{filepath}'")
    except Exception as e:
        raise IOError(f"Kritikus hiba a '{filepath}' kiírása közben: {e}")