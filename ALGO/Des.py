from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
import base64

def Des_Encrypt(msg):
    block_size = DES.block_size  # 8 octets
    iv = Random.new().read(block_size // 2)  # IV de 4 octets
    key = Random.new().read(8)  # Clé de 8 octets pour DES
    ctr = Counter.new(block_size * 4, prefix=iv, initial_value=0)
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    encrypted_message = iv + cipher.encrypt(msg.encode('ascii'))
    return key, base64.b64encode(encrypted_message).decode('ascii')

def Des_Decrypt(key, encrypted_message):
    block_size = DES.block_size  # 8 octets
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:block_size // 2]  # IV de 4 octets
    encrypted_message_ = encrypted_message[block_size // 2:]
    ctr = Counter.new(block_size * 4, prefix=iv, initial_value=0)
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    return cipher.decrypt(encrypted_message_).decode('ascii')

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
        key, encrypted_message = Des_Encrypt(msg_encrypt)
        print("Clé (en hexadécimal) :", key.hex())
        print("Message crypté :", encrypted_message)

    elif choice == 1:
        key_hex = input("Entrez la clé en hexadécimal : ")
        key = bytes.fromhex(key_hex)
        msg_decrypt = input("Entrez le message à déchiffrer : ")
        try:
            decrypted_message = Des_Decrypt(key, msg_decrypt)
            print("Message décrypté :", decrypted_message)
        except Exception as e:
            print("Erreur lors du déchiffrement :", str(e))

    elif choice == 2:
        print("Quitter le programme.")
        break

    else:
        print("Cette option n'existe pas !")

print("Programme terminé.")




