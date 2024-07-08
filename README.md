# voidChat: Secure Messaging Client and Server

## Overview

voidChat is a secure messaging client and server application written in Python. It utilizes RSA encryption to ensure message confidentiality and integrity. This README provides an overview of the system, setup instructions, and details on how to use the client and server components.


## Features

- **RSA Encryption**: Ensures secure message transmission.
- **Message Signing**: Provides message integrity and authenticity.
- **Chat Management**: Handles multiple chats with message history and unread message tracking.
- **Threaded Server**: Supports multiple clients simultaneously.

## Prerequisites

- Python 3.6 or higher
- Required Python libraries: `rsa`, `inquirer`, `socket`, `json`, `platform`, `queue`, `threading`, `datetime`, `os`, `time`, `base64`

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/srpiroliro/voidchat.git
    cd vchat
    ```

2. **Install required libraries:**
    ```sh
    pip install rsa inquirer
    ```

## Usage

### Running the Server

1. **Start the server:**
    ```sh
    python server.py
    ```

   The server will start listening on `127.0.0.1:1111`.

### Running the Client

1. **Start the client:**
    ```sh
    python client.py
    ```

2. **Generating RSA Keys:**
   If RSA keys are not found, the client will automatically generate a new pair.

3. **Connecting to the Server:**
   The client will attempt to connect to the server at `127.0.0.1:1111`.

4. **Using the Client:**
   - **Login**: The client will login to the server.
   - **Chat Management**: You can create new chats, switch between chats, rename chats, and delete chats.
   - **Sending Messages**: You can send messages to the selected chat.
   - **Receiving Messages**: The client listens for incoming messages and displays them in real-time.

## Code Structure

### Client (client.py)

- **Class `Client`**:
  - Manages connection, encryption, chat history, and user commands.
  - Methods for key generation, encryption/decryption, message signing/verification, and chat management.
  - Handles both sending and receiving messages using threads.

### Server (server.py)

- **Class `ClientThread`**:
  - Handles client connections, message parsing, and forwarding.
  - Verifies client messages and manages message queues for offline clients.

## Message Structure

Messages have the following JSON structure:
```json
{
  "s": "SENDER_PUB_KEY_HEX",
  "de": "DESTINATION_PUB_KEY_HEX",
  "da": "ENCRYPTED_DATA"
}
```

Encrypted data structure:
```json
{
  "t": "SECONDS_TIMESTAMP",
  "txt": "MESSAGE_TEXT",
  "sg": "SIGNATURE"
}
```

## Commands

Client supports the following commands:
- `!delete`: Delete the current chat or all chats if not in a chat.
- `!switch`: Switch to a different chat.
- `!rename`: Rename the current chat.
- `!quit`: Quit the client application.

## Notes

- Ensure the server is running before starting the client.
- Keep your private key secure and never share it.
- The client automatically saves chat history and unread messages.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgements

Special thanks to the contributors and open-source community for their support and resources.

---

Feel free to reach out for any questions or contributions. Enjoy secure chatting with vChat!
