import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # cryptography
import os
import copy

FILEPATH = 'crypto.json'

def save(data: dict, filepath: str):
    with open(filepath, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

def encrypt_data(texts: list[str]):
    key_bytes = AESGCM.generate_key(bit_length=256)
    data = {
        'type': 'cryptography',
        'key': key_bytes.hex(),
        'data': [],
        'nonce': []
    }
    aesgcm = AESGCM(key_bytes)

    for text in texts:
        nonce_bytes = os.urandom(12)
        crypto_bytes = aesgcm.encrypt(nonce_bytes, text.encode('utf-8'), None)

        data['data'].append(crypto_bytes.hex())
        data['nonce'].append(nonce_bytes.hex())

    save(data, 'encrypted.json')

def decrypt_data(filepath: str = 'encrypted.json'):
    with open(filepath, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    aesgcm = AESGCM(bytes.fromhex(data['key']))
    decrypted_list = []
    
    for i, text_hex in enumerate(data['data']):
        n_bytes = bytes.fromhex(data['nonce'][i])
        c_bytes = bytes.fromhex(text_hex)
        
        decrypted_text = aesgcm.decrypt(n_bytes, c_bytes, None).decode('utf-8')
        decrypted_list.append(decrypted_text)
    
    data['data'] = decrypted_list
    del data['nonce']
    
    save(data, 'decrypted.json')

def main():
    texts = [
        'Leandro',
        'Teste'
    ]

    #encrypt_data(texts)
    #decrypt_data()

if __name__ == '__main__':
    main()
