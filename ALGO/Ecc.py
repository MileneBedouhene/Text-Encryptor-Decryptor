import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import binascii

# Génération des clés privées et publiques ECC
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Chiffrement du message
def encrypt_message(public_key, message):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return (ephemeral_key.public_key(), iv, ciphertext, encryptor.tag)

# Déchiffrement du message
def decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag):
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Génération des clés ECC
private_key, public_key = generate_keys()

# Fonction pour vérifier les entrées hexadécimales
def get_hex_input(prompt):
    while True:
        try:
            hex_input = input(prompt)
            return bytes.fromhex(hex_input)
        except ValueError:
            print("Veuillez entrer une chaîne hexadécimale valide.")

# Demande de l'entrée de l'utilisateur
j = 0
while j != 2:
    print('Veuillez saisir une option :')
    print('0 - Pour chiffrer un texte.')
    print('1 - Pour déchiffrer un texte.')
    print('2 - Pour quitter.')
    j = int(input())
    
    if j == 0:
        message = input('Entrez votre message : ')
        ephemeral_public_key, iv, ciphertext, tag = encrypt_message(public_key, message)
        print(f"Message chiffré : {ciphertext.hex()}")
        print(f"Clé publique éphémère: {ephemeral_public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint).hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Tag: {tag.hex()}")

    elif j == 1:
        ciphertext = get_hex_input('Entrez votre message chiffré (en hex) : ')
        ephemeral_public_key_bytes = get_hex_input('Entrez la clé publique éphémère (en hex) : ')
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_key_bytes
        )
        iv = get_hex_input('Entrez l\'IV (en hex) : ')
        tag = get_hex_input('Entrez le tag (en hex) : ')
        decrypted_message = decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag)
        print(f"Message déchiffré : {decrypted_message}")

    elif j != 2:
        print("Cette option n'existe pas !")




