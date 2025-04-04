import sys
import unicodedata  

def remove_accents(s):
    nfkd_form = unicodedata.normalize('NFD', s) 
    return ''.join([c for c in nfkd_form if unicodedata.category(c) != 'Mn'])

def caesar_cipher(text, shift):
    text = text.lower()
    text = remove_accents(text)
        
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            pos = ord(char) - ord('a')
            new_pos = (pos + shift) % 26
            result += chr(new_pos + ord('a'))
        else:
            result += char
    return result

if __name__ == "__main__":
    text = sys.argv[1]
    shift = int(sys.argv[2])
    
    encrypted_text = caesar_cipher(text, shift)
    print(encrypted_text)
