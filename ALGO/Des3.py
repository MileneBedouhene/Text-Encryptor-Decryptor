from Crypto.Cipher import DES3
from Crypto import Random
import base64

def Des3_Encrypt(msg):
    block_size = DES3.block_size
    key = Random.new().read(24)  # La clé doit être de 24 octets pour DES3
    iv = Random.new().read(block_size)
    c = DES3.new(key, DES3.MODE_OFB, iv)
    encrypted_message = c.encrypt(msg.encode('ascii'))
    return key, base64.b64encode(iv + encrypted_message).decode('ascii')

def Des3_Decrypt(key, encrypted_message):
    encrypted_message_ = base64.b64decode(encrypted_message)
    iv = encrypted_message_[:DES3.block_size]  # Extraire l'IV
    encrypted_message_ = encrypted_message_[DES3.block_size:]  # Extraire le message chiffré
    d = DES3.new(key, DES3.MODE_OFB, iv)
    return d.decrypt(encrypted_message_).decode('ascii')

# Menu interaction with the user
choice = 0
while choice != 2:
    print('Veuillez saisir une option :')
    print('0 - Pour chiffrer un texte.')
    print('1 - Pour déchiffrer un texte.')
    print('2 - Pour quitter.')
    choice = int(input())
    
    if choice == 0:
        msg_encrypt = input("Entrez le message à crypter : ")
        key, encrypted_message = Des3_Encrypt(msg_encrypt)
        print("Clé (en hexadécimal) :", key.hex())
        print("Message crypté :", encrypted_message)

    elif choice == 1:
        key_hex = input("Entrez la clé en hexadécimal : ")
        key = bytes.fromhex(key_hex)
        msg_decrypt = input("Entrez le message à déchiffrer : ")
        try:
            decrypted_message = Des3_Decrypt(key, msg_decrypt)
            print("Message décrypté :", decrypted_message)
        except Exception as e:
            print("Erreur lors du déchiffrement :", str(e))

    elif choice == 2:
        print("Quitter le programme.")
        break

    else:
        print("Cette option n'existe pas !")

print("Programme terminé.")


