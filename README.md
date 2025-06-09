# Message-Encryption-and-Decryption-Using-AES

- Prompt the user to enter a message for encryption.
- Encrypt the message using AES in CBC mode.
- Save the encrypted message to a file named encrypted_message.bin.
- Use cipher.decrypt() to decrypt the encrypted_message.bin, and display the original
plaintext message.

![image](https://github.com/user-attachments/assets/13880895-b1b0-4777-b340-91b6290ad0e2)

<i> (Using Google Colab) </i><br>

This Python script encrypts and decrypts a user-provided message using AES in CBC
mode with the PyCryptodome library. It begins by taking a message input and encoding it
into bytes, then generates a random 16-byte key and IV (Initialization Vector) for AES-128
encryption. The message is padded to fit AES’s 16-byte block size requirement using
PKCS#7-like padding. The cipher encrypts the padded message, and the resulting
ciphertext along with the IV is saved to a binary file. For decryption, the file is read, the IV
and encrypted data are extracted, and the same key is used to initialize the cipher and
decrypt the message. After removing the padding, the original message is displayed,
demonstrating a complete encryption-decryption cycle</br>

<b>👨‍💻 Codes:</b>

<div class="code-cell"><code>
  
\# Run this code first
!pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

\# Prompt the user to enter a message for encryption
message = input("Enter a message to encrypt: ")
message_bytes = message.encode()

\# Generate key and IV. IV could be static or dynamic but its more secure if its
\# random
key = get_random_bytes(16)  # AES-128
with open ("aes.key", "wb") as f: # Write the AES Key to send to recipient
    data = f.write(key)
iv = get_random_bytes(16)   # Initialization vector make it random to more secure

\# Pad the message
\# Padding length calculation
padding_length = 16 - (len(message_bytes) % 16)

\# Apply padding
padded_message = message_bytes + bytes([padding_length] * padding_length)

\# Encrypt the message using AES CBC mode
cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = cipher_encrypt.encrypt(padded_message)

\# Show encrypted message in hex format
print("Encrypted message:", encrypted_data.hex())

\# Save the encrypted message + IV to a file
with open("encrypted_message.bin", "wb") as f:
    f.write(iv + encrypted_data)

\# Load the encrypted file and open decrypt it
with open("encrypted_message.bin", "rb") as f:
    file_data = f.read()
    iv_loaded = file_data[:16]
    encrypted_loaded = file_data[16:]

\# Decrypt the message
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv_loaded)
decrypted_padded = cipher_decrypt.decrypt(encrypted_loaded)

\# Remove padding
padding_length = decrypted_padded[-1]
decrypted_message = decrypted_padded[:-padding_length].decode()

\# Show the decrypted message
print("Decrypted message:", decrypted_message) </code>
</div>

<b>Reflection question:</b> What would happen if we always used the same encryption key
without an Initialization Vector (IV) when encrypting messages? What kind of attack could
happen, and how does an Initialization Vector (IV) solve this problem? </b>

<b>Answer:</b> If we always use the same encryption key and no IV (Initialization Vector) to
encrypt messages, then identical messages will always produce the same encrypted
output. This is a big problem because an attacker could start to notice patterns. For
example, if you send "login successful" often, the encrypted version of that message will
always look the same, so the attacker might guess what it means—even without knowing
the key. This is called a known-plaintext attack or pattern analysis.
An Initialization Vector (IV) solves this by adding a bit of randomness. Even if you send
the same message twice, the IV changes each time, so the encrypted result looks
different every time. This makes it much harder for attackers to find patterns or guess
what the original message was, keeping your data more secure.


