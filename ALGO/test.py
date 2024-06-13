import sys
import binascii
import os
from Crypto.Cipher import Blowfish, DES, DES3, AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import rsa
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64


################CESAR################

#CHIFFREMENT
def cesar_chiffre_mixte(texte, decalage):
    resultat = ""
    
    for char in texte:
        if char.isupper():
            # Décalage dans le rang de 65 ('A') à 90 ('Z')
            resultat += chr((ord(char) - 65 + decalage) % 26 + 65)
        elif char.islower():
            # Décalage dans le rang de 97 ('a') à 122 ('z')
            resultat += chr((ord(char) - 97 + decalage) % 26 + 97)
        else:
            # Si ce n'est pas une lettre, on le laisse inchangé
            resultat += char
            
    return resultat

#DECHIFFREMENT
def cesar_dechiffre_mixte(texte,decalage):
    resultat=''

    for char in texte:
        if char.isupper():
            # Décalage dans le rang de 65 ('A') à 90 ('Z')
            resultat += chr((ord(char) - 65 - decalage) % 26 + 65)
        elif char.islower():
            # Décalage dans le rang de 97 ('a') à 122 ('z')
            resultat += chr((ord(char) - 97 - decalage) % 26 + 97)
        else:
            # Si ce n'est pas une lettre, on le laisse inchangé
            resultat += char
            
    return resultat


########################################


################VIGENERE################

#GENERATION DE LA TABLE DE VIGENERE
def table_vigenere():
    table = []
    for i in range(26):
        row = []
        for j in range(26):
            row.append(chr((i + j) % 26 + ord('A')))
        table.append(row)
    return table


#EXTRACTION DE LA CLE DE CHIFFREMENT
def ckey(message, key):
    key = key.upper()
    ckey = key
    while len(ckey) < len(message):
        ckey += key
    return ckey[:len(message)]

#CHIFFREMENT
def vigenere_chiffre(message, key):
    key = ckey(message, key)
    table = table_vigenere()
    cipher_text = []
    
    for i in range(len(message)):
        char = message[i]
        if char.isalpha():
            row = ord(key[i]) - ord('A')
            if char.isupper():
                col = ord(char) - ord('A')
                cipher_text.append(table[row][col])
            else:
                col = ord(char) - ord('a')
                cipher_text.append(table[row][col].lower())
        else:
            cipher_text.append(char)
    
    return ''.join(cipher_text)

#DECHIFFREMENT
def vigenere_dechiffre(cipher_text, key):
    key = ckey(cipher_text, key)
    table = table_vigenere()
    message = []
    
    for i in range(len(cipher_text)):
        char = cipher_text[i]
        if char.isalpha():
            row = ord(key[i]) - ord('A')
            if char.isupper():
                col = table[row].index(char)
                message.append(chr(col + ord('A')))
            else:
                col = table[row].index(char.upper())
                message.append(chr(col + ord('a')))
        else:
            message.append(char)
    
    return ''.join(message)


#########################################


################RAILFENCE################

#CHIFFREMENT
def RailcipherText(clearText, key):
    result = ""
    matrix = [["" for x in range(len(clearText))] for y in range(key)]

    increment = 1
    row = 0
    col = 0

    for c in clearText:
        if row + increment < 0 or row + increment >= key:
            increment *= -1
        
        matrix[row][col] = c

        row += increment
        col += 1

    for rail in matrix:
        result += "".join(rail)

    return result

#DECHIFFREMENT
def RaildecipherText(cipherText, key):
    #CREATION D'UNE MATRICE
    matrix = [["" for _ in range(len(cipherText))] for _ in range(key)]
    
    #MARQUER LES POSITIONS AVEC '*'
    row = 0
    increment = 1
    for col in range(len(cipherText)):
        matrix[row][col] = '*'
        if row == 0:
            increment = 1
        elif row == key - 1:
            increment = -1
        row += increment
    
    #REMPLIR LA MATRICE
    idx = 0
    for r in range(key):
        for c in range(len(cipherText)):
            if matrix[r][c] == '*' and idx < len(cipherText):
                matrix[r][c] = cipherText[idx]
                idx += 1
    
    #LIRE LA MATRICE
    result = ""
    row = 0
    increment = 1
    for col in range(len(cipherText)):
        result += matrix[row][col]
        if row == 0:
            increment = 1
        elif row == key - 1:
            increment = -1
        row += increment
    
    return result

########################################


################BLOWFISH################

def Bpad(s):
    return s + (Blowfish.block_size - len(s) % Blowfish.block_size) * b'*'

def Bunpad(s):
    return s.rstrip(b'*')

#CHIFFREMENT
def BlowEncrypt(msg):
    key = Random.new().read(16)
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    encrypted_message = iv + cipher.encrypt(Bpad(msg.encode('ascii')))
    return key, base64.b64encode(encrypted_message).decode('ascii')

#DECHIFFREMENT
def BlowDecrypt(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message.encode('ascii'))
    iv = encrypted_message[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_message = Bunpad(cipher.decrypt(encrypted_message[Blowfish.block_size:]))
    return decrypted_message.decode('ascii')



###################################


################AES################

salt = b'\xa82\xf0\xde">C\x83rw\x8bw\xaa\x98\xa4\x00\x1a\x0e|(+N\x93\xba\xfc \xdeJ[S\xd3x'
password = "my password"
key = PBKDF2(password, salt, dkLen=32)

#CHIFFREMENT

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv, ciphered_data

#DECHIFFREMENT

def aes_decrypt(ciphered_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(ciphered_data), AES.block_size)
    return original.decode()



###################################


################DES################

#CHIFFREMENT
def Des_Encrypt(msg):
    block_size = DES.block_size  # 8 octets
    iv = Random.new().read(block_size // 2)  # IV de 4 octets
    key = Random.new().read(8)  # Clé de 8 octets pour DES
    ctr = Counter.new(block_size * 4, prefix=iv, initial_value=0)
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    encrypted_message = iv + cipher.encrypt(msg.encode('ascii'))
    return key, base64.b64encode(encrypted_message).decode('ascii')

#DECHIFFREMENT

def Des_Decrypt(key, encrypted_message):
    block_size = DES.block_size  # 8 octets
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:block_size // 2]  # IV de 4 octets
    encrypted_message_ = encrypted_message[block_size // 2:]
    ctr = Counter.new(block_size * 4, prefix=iv, initial_value=0)
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    return cipher.decrypt(encrypted_message_).decode('ascii')


####################################


################DES3################

#CHIFFREMENT

def Des3_Encrypt(msg):
    block_size = DES3.block_size
    key = Random.new().read(24)  # La clé doit être de 24 octets pour DES3
    iv = Random.new().read(block_size)
    c = DES3.new(key, DES3.MODE_OFB, iv)
    encrypted_message = c.encrypt(msg.encode('ascii'))
    return key, base64.b64encode(iv + encrypted_message).decode('ascii')


#DECHIFFREMENT
def Des3_Decrypt(key, encrypted_message):
    encrypted_message_ = base64.b64decode(encrypted_message)
    iv = encrypted_message_[:DES3.block_size]  # Extraire l'IV
    encrypted_message_ = encrypted_message_[DES3.block_size:]  # Extraire le message chiffré
    d = DES3.new(key, DES3.MODE_OFB, iv)
    return d.decrypt(encrypted_message_).decode('ascii')


###################################


################RSA################


#LE CHARGEMENT DE LA CLE PUBLIQUE A PARTIR DU FICHIER 
with open("C:\\Users\\milen\\OneDrive\\Desktop\\Crypto\\ALGO\\Rsa\\public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

#LE CHARGEMENT DE LA CLE PRIVE A PARTIR DU FICHIER
with open("C:\\Users\\milen\\OneDrive\\Desktop\\Crypto\\ALGO\\Rsa\\private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())


#CHIFFREMENT 
def RsaEncrypt_message():
    message = input("Entrez le message à chiffrer : ")
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    encrypt_file_path = input("Entrez le chemin pour enregistrer le fichier chiffré : ").strip()
    with open(encrypt_file_path, "wb") as f:
        f.write(encrypted_message)
        print(f"Message chiffré et enregistré dans '{encrypt_file_path}'.")



#DECHIFFREMEMNT

def RsaDecrypt_message():
    decrypt_file_path = input("Entrez le chemin du fichier à déchiffrer : ").strip()
    try:
        with open(decrypt_file_path, "rb") as f:
            encrypted_message = f.read()
        decrypted_message = rsa.decrypt(encrypted_message, private_key)
        print("Message déchiffré :", decrypted_message.decode())
    except FileNotFoundError:
        print("Le fichier spécifié est introuvable.")
    except rsa.DecryptionError:
        print("Erreur de déchiffrement. Assurez-vous que le fichier est correctement chiffré et que la clé privée est correcte.")
    except OSError as e:
        print(f"Erreur lors de l'ouverture du fichier : {e}")

###################################


################ECC################
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecc_encrypt(message, public_key):
    shared_key = public_key.exchange(ec.ECDH())
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return (ciphertext, encryptor.tag)

def ecc_decrypt(ciphertext, tag, private_key):
    shared_key = private_key.exchange(ec.ECDH())
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(tag), backend=default_backend())
    decryptor = aes_cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()



###################################


################SHA256#############
    

#HACHAGE

def hash_password(password):
    h = hashlib.new("SHA256")
    h.update(password.encode())
    return h.hexdigest()


###################################


################MAIN################

choice = 0
while choice != 11:
    print('Veuillez choisir un algorithme :')
    print('1 - César')
    print('2 - Vigenère')
    print('3 - Rail Fence')
    print('4 - Blowfish')
    print('5 - AES')
    print('6 - DES')
    print('7 - DES3')
    print('8 - RSA')
    print('9 - SHA256')
    print('10 - Pour quitter')
    choice = int(input())

    #CESAR
    if choice == 1:
        j=0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())

            if j==0:
                message = input('Entrez votre message : ')
                try:
                    clef = int(input('Entrez votre clef : '))  # Conversion de la clé en entier
                    if clef < 0:
                        raise ValueError("La clé doit être un entier positif")

                    else:   
                        # Appel de la fonction de chiffrement et affichage du résultat
                        print(f"Message chiffré : {cesar_chiffre_mixte(message, clef)}")
        
                except ValueError:
                    print("Veuillez entrer un nombre entier valide pour la clé.")
    

            elif j==1:
                message = input('Entrez votre message : ')
                try:
                    clef = int(input('Entrez votre clef : '))  # Conversion de la clé en entier
                    if clef < 0:
                        raise ValueError("La clé doit être un entier positif")
            
                    else :
                        # Appel de la fonction de chiffrement et affichage du résultat
                        print(f"Message dechiffré : {cesar_dechiffre_mixte(message, clef)}")
        
                except ValueError:
                    print("Veuillez entrer un nombre entier valide pour la clé.")

            elif j == 2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        
        if j == 3 :
            print("Vous avez quitter le programmme")
            sys.exit() 


    #VIGENERE
    elif choice == 2:
        j=0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())

            if j == 0:
                message = input('Entrez votre message : ')
                clef = input('Entrez votre clef (alphabétique) : ').upper()
                # Appel de la fonction de chiffrement et affichage du résultat
                print(f"Message chiffré : {vigenere_chiffre(message, clef)}")

            elif j == 1:
                message = input('Entrez votre message chiffré : ')
                clef = input('Entrez votre clef (alphabétique) : ').upper()
                # Appel de la fonction de déchiffrement et affichage du résultat
                print(f"Message déchiffré : {vigenere_dechiffre(message, clef)}")

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit() 

    #RAILFENCE           
    elif choice == 3:
        j=0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())

            if j == 0:
                message = input("Entrez le message à chiffrer : ")
                key = int(input("Entrez la clé (nombre de rails) : "))
                cipher_text = RailcipherText(message, key)
                print("Message chiffré :", cipher_text)

            elif j == 1:
                cipher_text = input("Entrez le message à déchiffrer : ")
                key = int(input("Entrez la clé (nombre de rails) : "))
                plain_text = RaildecipherText(cipher_text, key)
                print("Message déchiffré :", plain_text)

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit() 
            


    #BLOWFISH
    elif choice == 4:
        j= 0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())
    
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

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit()


    #AES
    elif choice == 5:
        j = 0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())
    
            if j == 0:
                message = input("Entrez le message à chiffrer : ")
                iv, ciphered_data = aes_encrypt(message, key)
                file_path = input("Entrez le chemin du fichier pour enregistrer le message crypté : ")
                with open(file_path, 'wb') as f:
                    f.write(iv)
                    f.write(ciphered_data)
                print("Message chiffré et enregistré dans le fichier.")

            elif j == 1:
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

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit()



    #DES
    elif choice == 6:
        j = 0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())
    
            if j == 0:
                msg_encrypt = input("Entrez le message à crypter : ")
                key, encrypted_message = Des_Encrypt(msg_encrypt)
                print("Clé (en hexadécimal) :", key.hex())
                print("Message crypté :", encrypted_message)

            elif j == 1:
                key_hex = input("Entrez la clé en hexadécimal : ")
                key = bytes.fromhex(key_hex)
                msg_decrypt = input("Entrez le message à déchiffrer : ")
                try:
                    decrypted_message = Des_Decrypt(key, msg_decrypt)
                    print("Message décrypté :", decrypted_message)
                except Exception as e:
                    print("Erreur lors du déchiffrement :", str(e))

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit()


    #DES3
    elif choice == 7:
        j = 0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())
    
            if j == 0:
                msg_encrypt = input("Entrez le message à crypter : ")
                key, encrypted_message = Des3_Encrypt(msg_encrypt)
                print("Clé (en hexadécimal) :", key.hex())
                print("Message crypté :", encrypted_message)

            elif j == 1:
                key_hex = input("Entrez la clé en hexadécimal : ")
                key = bytes.fromhex(key_hex)
                msg_decrypt = input("Entrez le message à déchiffrer : ")
                try:
                    decrypted_message = Des3_Decrypt(key, msg_decrypt)
                    print("Message décrypté :", decrypted_message)
                except Exception as e:
                    print("Erreur lors du déchiffrement :", str(e))

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit()

    #RSA
    elif choice == 8:
        j = 0
        while j!=3 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour déchiffrer un texte.')
            print('2 - Pour le retour')
            print('3 - Pour quitter.')
            j= int(input())
    
            if j == 0:
                RsaEncrypt_message()
            elif j == 1:
                RsaDecrypt_message()

            elif j ==2 :
                break

            elif j!=3 :
                print("cette option n'existe pas !")
        
        if j ==3 :
            print("Vous avez quitter le programmme")
            sys.exit()

    #SHA256
    elif choice == 9:
        j = 0
        while j!=2 :
            print('Veuillez saisir une option :')
            print('0 - Pour chiffrer un texte.')
            print('1 - Pour le retour')
            print('2 - Pour quitter.')
            j= int(input())
    
            if j == 0:
                user_password = input('Entrez votre mot de passe à chiffrer : ')
                hashed_password = hash_password(user_password)
                print(f"Message chiffré (hashé) : {hashed_password}")

            elif j ==1 :
                break
        
            elif j !=2 :
                print("Cette option n'existe pas !")

        if j ==2 :
            print("Vous avez quitter le programmme")
            sys.exit()

    #QUITTER 
    elif choice == 10:
        print("Vous avez quitter le programmme")
        sys.exit()

    elif choice == 11:
        print("Sélectionnez une option :")
        print("1. Générer des clés ECC")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        ecc_choix = int(input("Entrez votre choix (1-3) : "))
        if ecc_choix == 1:
            private_key, public_key = generate_ecc_keys()
            print("Clés ECC générées.")
            # Optionally save keys to files
        elif ecc_choix == 2:
            message = input("Entrez le message à chiffrer : ")
            # Assuming public_key is already available
            ciphertext, tag = ecc_encrypt(message, public_key)
            print(f"Message chiffré : {base64.b64encode(ciphertext).decode()} et tag : {base64.b64encode(tag).decode()}")
        elif ecc_choix == 3:
            ciphertext = base64.b64decode(input("Entrez le message chiffré : ").encode())
            tag = base64.b64decode(input("Entrez le tag : ").encode())
            # Assuming private_key is already available
            decrypted_message = ecc_decrypt(ciphertext, tag, private_key)
            print(f"Message déchiffré : {decrypted_message}")
        else:
            print("Choix invalide")