from Crypto.Cipher import Blowfish
from Crypto import Random
import base64

def pad(s):
    return s + (Blowfish.block_size - len(s) % Blowfish.block_size) * b'*'

def unpad(s):
    return s.rstrip(b'*')

def BlowEncrypt(msg):
    key = Random.new().read(16)
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    encrypted_message = iv + cipher.encrypt(pad(msg.encode('ascii')))
    return key, base64.b64encode(encrypted_message).decode('ascii')

def BlowDecrypt(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message.encode('ascii'))
    iv = encrypted_message[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[Blowfish.block_size:]))
    return decrypted_message.decode('ascii')

# Menu interaction with the user
j= 0
while j != 2:
    print('Veuillez saisir une option :')
    print('0-Pour chiffrer un texte.')
    print('1-Pour déchiffrer un texte.')
    print('2-Pour quitter.')
    j = int(input())
    
    if j == 0:
        msg_encrypt = input("Entrez le message à crypter : ")
        key, encrypted_message = BlowEncrypt(msg_encrypt)
        print("Clé :", key.hex())
        print("Message crypté :", encrypted_message)

    elif j == 1:
        key_hex = input("Entrez la clé en hexadécimal : ")
        key = bytes.fromhex(key_hex)
        msg_decrypt = input("Entrez le message à déchiffrer : ")
        try:
            decrypted_message = BlowDecrypt(key, msg_decrypt)
            print("Message décrypté :", decrypted_message)
        except Exception as e:
            print("Erreur lors du déchiffrement :", str(e))

    elif j != 2:
        print("Cette option n'existe pas !")

print("Programme terminé.")