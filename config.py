import json
import base64
from jsonschema import validate, ValidationError

def load_cipher_config(config_path: str, schema_path: str) -> dict:
    """
    Beolvassa és validálja a titkosító konfigurációját, 
    majd kigyűjti és megfelelő formátumba hozza a paramétereket.
    """
    
    # 1. Beolvassuk a séma (szabályrendszer) és a konfiguráció (adat) fájlokat
    with open(schema_path, 'r', encoding='utf-8') as sf:
        schema = json.load(sf)
        
    with open(config_path, 'r', encoding='utf-8') as cf:
        config = json.load(cf)

    # 2. Validáljuk az adatokat a JSON séma alapján
    try:
        validate(instance=config, schema=schema)
    except ValidationError as e:
        # Ha valami nem felel meg a sémának (pl. 64-nél nagyobb blocksize), itt elkapjuk
        raise ValueError(f"Érvénytelen konfiguráció a JSON fájlban! Hiba: {e.message}")

    # 3. Kigyűjtjük az egyszerű (szöveges/számos) paramétereket
    blocksize = config["blocksize"]
    cipher_name = config["cipher"]
    mode = config["mode"]
    padding = config["padding"]

    # 4. A 'key' kötelező, és Base64 kódolású. Ezt dekódoljuk nyers bájtokká.
    try:
        key_bytes = base64.b64decode(config["key"])
    except Exception:
        raise ValueError("A megadott kulcs (key) nem érvényes Base64 formátumú!")

    # 5. Az 'iv' (Kezdeti Vektor) opcionális a sémában (mert ECB módhoz nem kell)
    iv_bytes = None
    if "iv" in config:
        try:
            iv_bytes = base64.b64decode(config["iv"])
        except Exception:
            raise ValueError("A megadott IV nem érvényes Base64 formátumú!")
            
    # +1 Extra logikai ellenőrzés: ha nem ECB módban vagyunk, muszáj lennie IV-nek
    if mode != "ECB" and iv_bytes is None:
        raise ValueError(f"Az '{mode}' működési módhoz kötelező IV-t (kezdeti vektort) megadni a configban!")

    # 6. Visszaadjuk az összes szükséges paramétert egy tiszta szótár (dictionary) formájában
    return {
        "blocksize": blocksize,
        "cipher": cipher_name,
        "mode": mode,
        "padding": padding,
        "key": key_bytes,
        "iv": iv_bytes
    }