# Text Encryptor/Decryptor
Ce projet est un outil simple pour chiffrer et déchiffrer du texte en utilisant divers algorithmes de chiffrement.

Les algorithmes de chiffrement implémentés dans ce projet sont :
### César : 
Le chiffre de César, attribué à Jules César, date d'environ 58 avant J.-C. Utilisé pour des communications militaires, il est très vulnérable, car un attaquant peut facilement le décrypter en essayant les 25 décalages possibles.
### Vigenère : 
Le chiffre de Vigenère, créé par Blaise de Vigenère en 1586, utilise un mot-clé pour effectuer des substitutions de lettres. Longtemps jugé incassable, il est aujourd'hui vulnérable aux analyses cryptographiques.
### Rail Fence : 
Le chiffre Rail Fence, utilisé depuis la Révolution américaine, réorganise les lettres du texte en les écrivant en zigzag sur plusieurs lignes. Il est vulnérable aux attaques simples.
### Blowfish : 
Blowfish, créé par Bruce Schneier en 1993, est un algorithme de chiffrement rapide et sécurisé avec des clés de 32 à 448 bits. Il est robuste mais souvent remplacé par AES.
### AES : 
AES (Advanced Encryption Standard) est un algorithme de chiffrement symétrique largement utilisé depuis 2001 pour sécuriser des données sensibles. Il offre une forte sécurité avec des clés de 128, 192 ou 256 bits, remplaçant efficacement le DES.
### DES : 
DES (Data Encryption Standard) est un algorithme de chiffrement symétrique développé dans les années 1970, utilisant des clés de 56 bits. Il a été une norme de chiffrement largement utilisée, mais sa sécurité est devenue insuffisante face aux avancées technologiques modernes.
### 3DES : 
3DES (Triple DES) est une extension du DES qui améliore sa sécurité en appliquant l'algorithme DES trois fois avec des clés différentes.
### RSA : 
RSA est un algorithme de cryptographie à clé publique inventé en 1977 par Ron Rivest, Adi Shamir et Leonard Adleman, basé sur la factorisation de grands nombres entiers en nombres premiers, largement utilisé pour le chiffrement et la signature numérique dans de nombreux protocoles de sécurité.
### ECC : 
ECC (Elliptic Curve Cryptography) est un type d'algorithme de cryptographie à clé publique basé sur les courbes elliptiques. Il est utilisé pour le chiffrement et la signature numérique, offrant une sécurité élevée avec des clés plus courtes par rapport aux autres algorithmes comme RSA.
### SHA-256 : 
SHA-256 est une fonction de hachage cryptographique réputée pour être irréversible, ce qui signifie qu'il est pratiquement impossible de retrouver les données d'entrée à partir de l'empreinte numérique générée par la fonction.

## Description :
### Dossier "ALGO" :
Vous trouverez les codes individuels de chaque algorithme cité ci-dessus (vous pouvez les tester individuellement).

### Fichier "Main" :
Vous trouverez un code qui contient tous les algorithmes cités ci-dessus (avec le choix de l'utilisateur), sauf pour Ecc.

### Fichier "Interface" :
Vous trouverez une interface graphique pour les algorithmes suivants : César, Vigenère, Rail Fence.
