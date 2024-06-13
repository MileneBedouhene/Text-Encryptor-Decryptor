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

def RaildecipherText(cipherText, key):
    # Create the empty matrix
    matrix = [["" for _ in range(len(cipherText))] for _ in range(key)]
    
    # Mark the positions with '*'
    row = 0
    increment = 1
    for col in range(len(cipherText)):
        matrix[row][col] = '*'
        if row == 0:
            increment = 1
        elif row == key - 1:
            increment = -1
        row += increment
    
    # Fill the matrix with the ciphertext
    idx = 0
    for r in range(key):
        for c in range(len(cipherText)):
            if matrix[r][c] == '*' and idx < len(cipherText):
                matrix[r][c] = cipherText[idx]
                idx += 1
    
    # Read the matrix to reconstruct the plaintext
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

j = 0
while j != 2:
    print('Veuillez saisir une option :')
    print('0 - Pour chiffrer un texte.')
    print('1 - Pour déchiffrer un texte.')
    print('2 - Pour quitter.')
    j = int(input())
    
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

    elif j == 2:
        print("Quitter le programme.")
        break

    else:
        print("Cette option n'existe pas !")

print("Programme terminé.")
