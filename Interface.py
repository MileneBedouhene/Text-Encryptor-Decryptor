import customtkinter as ctk
from tkinter import messagebox
import sys

# Algorithme de César
def cesar_chiffre_mixte(texte, decalage):
    resultat = ""
    for char in texte:
        if char.isupper():
            resultat += chr((ord(char) - 65 + decalage) % 26 + 65)
        elif char.islower():
            resultat += chr((ord(char) - 97 + decalage) % 26 + 97)
        else:
            resultat += char
    return resultat

def cesar_dechiffre_mixte(texte, decalage):
    resultat = ""
    for char in texte:
        if char.isupper():
            resultat += chr((ord(char) - 65 - decalage) % 26 + 65)
        elif char.islower():
            resultat += chr((ord(char) - 97 - decalage) % 26 + 97)
        else:
            resultat += char
    return resultat

# Algorithme de Vigenère
def table_vigenere():
    table = []
    for i in range(26):
        row = []
        for j in range(26):
            row.append(chr((i + j) % 26 + ord('A')))
        table.append(row)
    return table

def ckey(message, key):
    key = key.upper()
    ckey = key
    while len(ckey) < len(message):
        ckey += key
    return ckey[:len(message)]

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

# Algorithme Rail Fence
def cipherText(clearText, key):
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

def decipherText(cipherText, key):
    matrix = [["" for _ in range(len(cipherText))] for _ in range(key)]
    
    row = 0
    increment = 1
    for col in range(len(cipherText)):
        matrix[row][col] = '*'
        if row == 0:
            increment = 1
        elif row == key - 1:
            increment = -1
        row += increment
    
    idx = 0
    for r in range(key):
        for c in range(len(cipherText)):
            if matrix[r][c] == '*' and idx < len(cipherText):
                matrix[r][c] = cipherText[idx]
                idx += 1
    
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

# Interface graphique
def on_start():
    root.destroy()
    show_algorithm_selection()

def on_quit():
    sys.exit()

def show_algorithm_selection():
    algorithm_window = ctk.CTk()
    algorithm_window.title("Sélection de l'algorithme")
    algorithm_window.geometry("600x400")

    label = ctk.CTkLabel(algorithm_window, text="Sélectionnez un algorithme de cryptographie", font=("Arial", 24))
    label.pack(pady=50)

    cesar_button = ctk.CTkButton(algorithm_window, text="César", command=lambda: open_algorithm_window(algorithm_window, "cesar"))
    vigenere_button = ctk.CTkButton(algorithm_window, text="Vigenère", command=lambda: open_algorithm_window(algorithm_window, "vigenere"))
    rail_fence_button = ctk.CTkButton(algorithm_window, text="Rail Fence", command=lambda: open_algorithm_window(algorithm_window, "rail_fence"))

    cesar_button.pack(pady=10)
    vigenere_button.pack(pady=10)
    rail_fence_button.pack(pady=10)

    quit_button = ctk.CTkButton(algorithm_window, text="Quitter", command=on_quit)
    quit_button.pack(side="right", padx=20, pady=20)

    algorithm_window.mainloop()

    algorithm_window.mainloop()

def open_algorithm_window(prev_window, algorithm):
    prev_window.destroy()

    algo_window = ctk.CTk()
    algo_window.title(f"Algorithme {algorithm.capitalize()}")
    algo_window.geometry("600x400")

    label = ctk.CTkLabel(algo_window, text=f"{algorithm.capitalize()} Chiffrement et Déchiffrement", font=("Arial", 24))
    label.pack(pady=20)

    message_label = ctk.CTkLabel(algo_window, text="Entrez votre message:")
    message_label.pack(pady=5)
    message_entry = ctk.CTkEntry(algo_window)
    message_entry.pack(pady=5)

    key_label = ctk.CTkLabel(algo_window, text="Entrez la clé (décalage):" if algorithm == "cesar" else "Entrez la clé (texte):" if algorithm == "vigenere" else "Entrez le nombre de rails:")
    key_label.pack(pady=5)
    key_entry = ctk.CTkEntry(algo_window)
    key_entry.pack(pady=5)

    def encrypt_message():
        message = message_entry.get()
        key = key_entry.get()
        if algorithm == "cesar":
            encrypted_message = cesar_chiffre_mixte(message, int(key))
        elif algorithm == "vigenere":
            encrypted_message = vigenere_chiffre(message, key)
        elif algorithm == "rail_fence":
            encrypted_message = cipherText(message, int(key))
        
        show_result_window(f"Message chiffré : {encrypted_message}")

    def decrypt_message():
        message = message_entry.get()
        key = key_entry.get()
        if algorithm == "cesar":
            decrypted_message = cesar_dechiffre_mixte(message, int(key))
        elif algorithm == "vigenere":
            decrypted_message = vigenere_dechiffre(message, key)
        elif algorithm == "rail_fence":
            decrypted_message = decipherText(message, int(key))
        
        show_result_window(f"Message déchiffré : {decrypted_message}")

    encrypt_button = ctk.CTkButton(algo_window, text="Chiffrer", command=encrypt_message)
    decrypt_button = ctk.CTkButton(algo_window, text="Déchiffrer", command=decrypt_message)

    encrypt_button.pack(pady=10)
    decrypt_button.pack(pady=10)

    return_button = ctk.CTkButton(algo_window, text="Retour", command=lambda: on_return(algo_window, prev_window))
    return_button.pack(side="left", padx=20, pady=20)

    quit_button = ctk.CTkButton(algo_window, text="Quitter", command=on_quit)
    quit_button.pack(side="right", padx=20, pady=20)

    algo_window.mainloop()

def on_return(algo_window, prev_window):
    algo_window.destroy()
    prev_window.deiconify()

def show_result_window(message):
    result_window = ctk.CTk()
    result_window.title("Résultat")
    result_window.geometry("600x400")

    label = ctk.CTkLabel(result_window, text=message, font=("Arial", 24))
    label.pack(pady=100)

    ok_button = ctk.CTkButton(result_window, text="OK", command=result_window.destroy)
    ok_button.pack(pady=20)

    result_window.mainloop()

# Fenêtre d'accueil
root = ctk.CTk()
root.title("Cryptographie")
root.geometry("600x400")

label = ctk.CTkLabel(root, text="Cryptographie", font=("Arial", 36))
label.pack(pady=100)

start_button = ctk.CTkButton(root, text="Commencer", command=on_start)
start_button.pack(side="right", padx=20, pady=20)

quit_button = ctk.CTkButton(root, text="Quitter", command=on_quit)
quit_button.pack(side="left", padx=20, pady=20)

root.mainloop()




