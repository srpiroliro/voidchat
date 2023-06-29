# voidchat

## Message Structure:
```
    "{sender_public_key}|{receiver_public_key}|{encrypted_message}"
```

## TO DO:
- [ ] implement encryption (https://www.section.io/engineering-education/rsa-encryption-and-decryption-in-python/)
    - use 512bit keys (maybe less?)
- encrypt message with private key, reciever decrypts with public key