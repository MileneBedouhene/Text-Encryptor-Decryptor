# GENERATION DE LA TABLE DE VIGENERE
def table_vigenere():
    table = []
    for i in range(26):
        row = []
        for j in range(26):
            row.append(chr((i + j) % 26 + ord('A')))
        table.append(row)
    return table

# EXTRACTION DE LA CLE DE CHIFFREMENT
def ckey(message, key):
    key = key.upper()
    ckey = key
    while len(ckey) < len(message):
        ckey += key
    return ckey[:len(message)]

# CHIFFREMENT
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

# DECHIFFREMENT
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

# Demande de l'entrée de l'utilisateur
j = 0
while j != 2:
    print('Veuillez saisir une option :')
    print('0-Pour chiffrer un texte.')
    print('1-Pour déchiffrer un texte.')
    print('2-Pour quitter.')
    j = int(input())
    
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

    elif j != 2:
        print("Cette option n'existe pas !")
