import rsa

# Charger la clé publique depuis le fichier
with open("C:/Users/milen/OneDrive/Desktop/Crypto/ALGO/Rsa/public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

# Charger la clé privée depuis le fichier
with open("C:/Users/milen/OneDrive/Desktop/Crypto/ALGO/Rsa/private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

def encrypt_message():
    message = input("Entrez le message à chiffrer : ")
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    encrypt_file_path = input("Entrez le chemin pour enregistrer le fichier chiffré : ").strip()
    with open(encrypt_file_path, "wb") as f:
        f.write(encrypted_message)
    print(f"Message chiffré et enregistré dans '{encrypt_file_path}'.")

def decrypt_message():
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

choice = 0
while choice != 2:
    print('Veuillez saisir une option :')
    print('0 - Pour chiffrer un texte.')
    print('1 - Pour déchiffrer un texte.')
    print('2 - Pour quitter.')
    choice = int(input())
    
    if choice == 0:
        encrypt_message()
    elif choice == 1:
        decrypt_message()
    elif choice == 2:
        print("Quitter le programme.")
        break
    else:
        print("Cette option n'existe pas !")

print("Programme terminé.")

