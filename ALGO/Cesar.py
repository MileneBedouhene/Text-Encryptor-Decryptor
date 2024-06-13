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
    

# Demande de l'entrée de l'utilisateur
j=0
while j!=2 :

    print('Veuillez saisir une option :')
    print('0-Pour chiffrer un texte.')
    print('1-Pour déchiffrer un texte.')
    print('2-Pour quitter.')
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


    elif j!=2:
        print("cette option n'existe pas !")




