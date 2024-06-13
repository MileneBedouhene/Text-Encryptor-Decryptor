from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

salt = b'\xa82\xf0\xde">C\x83rw\x8bw\xaa\x98\xa4\x00\x1a\x0e|(+N\x93\xba\xfc \xdeJ[S\xd3x'
password = "my password"
key = PBKDF2(password, salt, dkLen=32)

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv, ciphered_data

def aes_decrypt(ciphered_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(ciphered_data), AES.block_size)
    return original.decode()

choice = 0
while choice != 3:
    print('Veuillez saisir une option :')
    print('0 - Pour chiffrer un texte.')
    print('1 - Pour déchiffrer un texte.')
    print('2 - Pour quitter.')
    choice = int(input())
    
    if choice == 0:
        message = input("Entrez le message à chiffrer : ")
        iv, ciphered_data = aes_encrypt(message, key)
        file_path = input("Entrez le chemin du fichier pour enregistrer le message crypté : ")
        with open(file_path, 'wb') as f:
            f.write(iv)
            f.write(ciphered_data)
        print("Message chiffré et enregistré dans le fichier.")

    elif choice == 1:
        file_path = input("Entrez le chemin du fichier contenant le message crypté : ")
        if not os.path.isfile(file_path):
            print("Le fichier n'existe pas.")
            continue
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            decrypt_data = f.read()
        try:
            original = aes_decrypt(decrypt_data, key, iv)
            print("Message déchiffré :", original)
        except Exception as e:
            print("Erreur lors du déchiffrement :", str(e))

    elif choice == 2:
        print("Quitter le programme.")
        break

    else:
        print("Cette option n'existe pas !")

print("Programme terminé.")


