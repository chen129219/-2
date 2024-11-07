import tkinter as tk
from tkinter import messagebox

# Simplified AES (S-AES) parameters
SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INVERSE_SBOX = [SBOX.index(x) for x in range(16)]
RCON1 = 0x80
RCON2 = 0x30

def nibble_substitution(s):
    return [SBOX[b] for b in s]

def inverse_nibble_substitution(s):
    return [INVERSE_SBOX[b] for b in s]

def shift_row(s):
    return [s[0], s[1], s[3], s[2]]

def inverse_shift_row(s):
    return [s[0], s[1], s[3], s[2]]

def add_round_key(s, k):
    return [si ^ ki for si, ki in zip(s, k)]

def key_expansion(key):
    w = [0] * 6
    w[0] = key >> 8
    w[1] = key & 0xFF
    w[2] = w[0] ^ RCON1 ^ (SBOX[w[1] >> 4] << 4 | SBOX[w[1] & 0xF])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ RCON2 ^ (SBOX[w[3] >> 4] << 4 | SBOX[w[3] & 0xF])
    w[5] = w[4] ^ w[3]
    return w

def state_from_int(n):
    return [(n >> 12) & 0xF, (n >> 8) & 0xF, (n >> 4) & 0xF, n & 0xF]

def state_to_int(s):
    return (s[0] << 12) | (s[1] << 8) | (s[2] << 4) | s[3]

def s_aes_decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(state_from_int(ciphertext), state_from_int((w[4] << 8) | w[5]))
    state = inverse_shift_row(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, state_from_int((w[2] << 8) | w[3]))
    state = inverse_shift_row(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, state_from_int((w[0] << 8) | w[1]))
    return state_to_int(state)

def decrypt():
    try:
        ciphertext = int(ciphertext_entry.get(), 2)
        key = int(key_entry.get(), 2)
    except ValueError:
        messagebox.showerror("Error", "Both ciphertext and key must be 16-bit binary strings")
        return

    plaintext = s_aes_decrypt(ciphertext, key)
    plaintext_label.config(text="Plaintext: " + format(plaintext, '016b'))

# Set up the main application window
root = tk.Tk()
root.title("S-AES Decryptor")

# Create and place widgets
tk.Label(root, text="密文 (16-bit):").pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

tk.Label(root, text="密钥 (16-bit):").pack()
key_entry = tk.Entry(root)
key_entry.pack()

decrypt_button = tk.Button(root, text="解密", command=decrypt)
decrypt_button.pack()

plaintext_label = tk.Label(root, text="明文:")
plaintext_label.pack()

# Start the GUI loop
root.mainloop()

