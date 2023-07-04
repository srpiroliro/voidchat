# voidchat

## Message Structure:
```
    "{sender_public_key}|{receiver_public_key}|{encrypted_message}"
```

## TO DO:
- [x] implement encryption (https://www.section.io/engineering-education/rsa-encryption-and-decryption-in-python/)
    - use 512bit keys (maybe less?)t m
- [x] ~~encrypessage with private key, reciever decrypts with public key~~ encrypt with receivers public key and add a signature
- [x] when encrypting/decrypting, avoid encrypting both times, use signatures.
- [ ] save private key under password
- [ ] implement hybrid encryption
    - [ ] generate symetric keys (for bulk data sharing)
- [ ] improve login
- [ ] add commands:
    - [ ] `!rename NEW_CHAT_NAME`.
    - [ ] `!close` close current chat.
    - [ ] `!exit` close the entire connection.
    - [ ] `!delete` deletes the current chat.
    - [ ] `!deleteall` deletes all opened chats.