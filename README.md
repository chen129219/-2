1.

根据S-AES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是16bit的数据和16bit的密钥，输出是16bit的密文。


![0a22f1a875a12afa361e5af25f9f1a9a](https://github.com/user-attachments/assets/8783338f-4c6f-472a-97fa-f8e764127c6b)

2.

交叉测试

输入密钥和明文加密得到密文

![226e3e4d8d6f0d58ad7f9be2c2f5d251](https://github.com/user-attachments/assets/21e6039c-70d5-46b3-b5c9-1c2d54468b61)

输入得到的密文和对应的密钥解密得到原本的明文

![096482d6a085f5c128f6eea26c722e9f](https://github.com/user-attachments/assets/78055415-85f2-47c7-a101-b1775988b10e)

3.

考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串(很可能是乱码)。

![26d8e9e985d3a197146eac811194bf9b](https://github.com/user-attachments/assets/6ac4e058-1606-40c5-80b1-959889806ced)


4.

多重加密

![0cbeb8f3a835efd43980224e675290af](https://github.com/user-attachments/assets/d37cbcc9-2902-4bfc-990f-196d6711d5a5)


5.

基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。注意初始向量(16 bits) 的生成，并需要加解密双方共享。
在CBC模式下进行加密，并尝试对密文分组进行替换或修改，然后进行解密，对比篡改密文前后的解密结果。


![787b23ccf9513f8a35a80d20098aadbe](https://github.com/user-attachments/assets/3aef3043-c891-4c7f-975f-5edf083cd283)

