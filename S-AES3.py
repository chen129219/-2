# 定义S-AES的S盒和逆S盒
S_BOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

INV_S_BOX = [
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
]

# 定义密钥调度常数
RCON1, RCON2 = 0x80, 0x30

# 在GF(2^4)域中进行乘法运算
def mult(p1, p2):
    """Galois Field (GF(2^4)) multiplication of p1 and p2."""
    p = 0
    while p2:
        if p2 & 0x1:
            p ^= p1
        p1 <<= 1
        if p1 & 0x10:
            p1 ^= 0b11  # x^4 + x + 1 (modulus polynomial)
        p2 >>= 1
    return p & 0xF


# 在S-AES中进行轮密钥加操作（异或操作）
def add_key(s1, s2):
    """Add two keys in S-AES (xor operation)."""
    return [i ^ j for i, j in zip(s1, [(s2 >> 4 * (1 - i % 2)) & 0xF for i in range(4)])]

# 使用给定的S盒替换nibbles
def sub_nibbles(sbox, s):
    """Substitute nibbles using the given S-Box."""
    return [sbox[i] for i in s]
# 行移位操作

def shift_rows(s):
    """Shift rows operation."""
    return [s[0], s[1], s[3], s[2]]
# S-AES的列混淆操作
def mix_columns(s):
    """Mix columns operation for S-AES."""
    return [
        s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
        s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])
    ]

# S-AES的密钥扩展操作
def key_expansion(key):
    """Key expansion for S-AES."""
    w = [0] * 6
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    w[2] = w[0] ^ RCON1 ^ (S_BOX[w[1] >> 4] << 4 | S_BOX[w[1] & 0xF])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ RCON2 ^ (S_BOX[w[3] >> 4] << 4 | S_BOX[w[3] & 0xF])
    w[5] = w[4] ^ w[3]
    return [w[0] << 8 | w[1], w[2] << 8 | w[3], w[4] << 8 | w[5]]

# S-AES加密函数
def encrypt(plaintext, key):
    """Encrypts a block of plaintext with S-AES."""
    key_schedule = key_expansion(key)
    state = add_key(plaintext, key_schedule[0])

    state = sub_nibbles(S_BOX, state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_key(state, key_schedule[1])

    state = sub_nibbles(S_BOX, state)
    state = shift_rows(state)
    state = add_key(state, key_schedule[2])

    return state

# S-AES解密函数
def decrypt(ciphertext, key):
    """Decrypts a block of ciphertext with S-AES."""
    key_schedule = key_expansion(key)

    state = add_key(ciphertext, key_schedule[2])
    state = shift_rows(state)
    state = sub_nibbles(INV_S_BOX, state)

    state = add_key(state, key_schedule[1])
    state = mix_columns(state)
    state = shift_rows(state)
    state = sub_nibbles(INV_S_BOX, state)

    state = add_key(state, key_schedule[0])

    return state

# 将字符串转换为nibbles列表
def str_to_nibbles(s):
    """Convert a string to a list of nibbles."""
    return [(ord(s[i // 2]) >> (4 * (1 - i % 2))) & 0xF for i in range(len(s) * 2)]
# 将nibbles列表转换回字符串
def nibbles_to_str(nibbles):
    """Convert a list of nibbles back to a string."""
    result = []
    for i in range(0, len(nibbles), 2):
        result.append(chr((nibbles[i] << 4) | nibbles[i + 1]))
    return ''.join(result)


# Example
key = 0b0100101011110100
plaintext = "AB"
plaintext_nibbles = str_to_nibbles(plaintext)

ciphertext_nibbles = encrypt(plaintext_nibbles, key)
ciphertext = nibbles_to_str(ciphertext_nibbles)
print(f"Ciphertext: {list(map(hex, ciphertext_nibbles))} -> {ciphertext!r}")

decrypted_nibbles = decrypt(ciphertext_nibbles, key)
decrypted_text = nibbles_to_str(decrypted_nibbles)
print(f"Decrypted: {list(map(hex, decrypted_nibbles))} -> {decrypted_text!r}")

import tkinter as tk
from tkinter import messagebox

# 解密按钮事件处理函数
def on_encrypt():
    try:
        key = int(entry_key.get(), 2)
        plaintext = entry_plaintext.get()

        if len(plaintext) != 2:
            raise ValueError("Plaintext must be exactly 2 characters!")

        plaintext_nibbles = str_to_nibbles(plaintext)
        ciphertext_nibbles = encrypt(plaintext_nibbles, key)
        ciphertext = nibbles_to_str(ciphertext_nibbles)

        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, ciphertext)

    except ValueError as e:
        messagebox.showerror("Error", f"Invalid input: {e}")

def on_decrypt():
    try:
        key = int(entry_key.get(), 2)
        ciphertext = entry_ciphertext.get()

        if len(ciphertext) != 2:
            raise ValueError("Ciphertext must be exactly 2 characters!")

        ciphertext_nibbles = str_to_nibbles(ciphertext)
        decrypted_nibbles = decrypt(ciphertext_nibbles, key)
        decrypted_text = nibbles_to_str(decrypted_nibbles)

        entry_decrypted.delete(0, tk.END)
        entry_decrypted.insert(tk.END, decrypted_text)

    except ValueError as e:
        messagebox.showerror("Error", f"Invalid input: {e}")
# 初始化主窗口
root = tk.Tk()
root.title("S-AES Encryption")

# 创建并放置组件
tk.Label(root, text="Key :").grid(row=0, column=0, sticky=tk.W)
entry_key = tk.Entry(root)
entry_key.grid(row=0, column=1, columnspan=2, sticky=tk.EW)

tk.Label(root, text="Plaintext (2 chars):").grid(row=1, column=0, sticky=tk.W)
entry_plaintext = tk.Entry(root)
entry_plaintext.grid(row=1, column=1, columnspan=2, sticky=tk.EW)

btn_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt)
btn_encrypt.grid(row=2, column=1, sticky=tk.EW)

tk.Label(root, text="Ciphertext (2 chars):").grid(row=3, column=0, sticky=tk.W)
entry_ciphertext = tk.Entry(root)
entry_ciphertext.grid(row=3, column=1, columnspan=2, sticky=tk.EW)

btn_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt)
btn_decrypt.grid(row=4, column=1, sticky=tk.EW)

tk.Label(root, text="Decrypted:").grid(row=5, column=0, sticky=tk.W)
entry_decrypted = tk.Entry(root)
entry_decrypted.grid(row=5, column=1, columnspan=2, sticky=tk.EW)
# 启动主循环
root.mainloop()
