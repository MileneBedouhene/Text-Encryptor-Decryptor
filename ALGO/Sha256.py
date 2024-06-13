import hashlib

def hash_password(password):
    h = hashlib.new("SHA256")
    h.update(password.encode())
    return h.hexdigest()

# Boucle pour permettre à l'utilisateur de chiffrer plusieurs mots de passe
j = 0
while j != 1:
    print('Veuillez saisir une option :')
    print('0-Pour chiffrer un texte.')
    print('1-Pour quitter.')
    j = int(input())
    
    if j == 0:
        user_password = input('Entrez votre mot de passe à chiffrer : ')
        hashed_password = hash_password(user_password)
        print(f"Message chiffré (hashé) : {hashed_password}")
    
    elif j != 1:
        print("Cette option n'existe pas !")
        
