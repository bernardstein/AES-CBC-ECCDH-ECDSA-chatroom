# Flask Server with HTML, JS Combined, and Digital Signatures
from flask import Flask, request
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES
import base64

app = Flask(__name__)
socketio = SocketIO(app)
connected_clients = {}  # Track connected clients by session ID and their public keys

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Chat Room</title>
        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/elliptic/6.5.4/elliptic.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f0f0f0;
                color: #333;
                margin: 0;
                padding: 0;
                display: grid;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            #chat {
                width: 400px;
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }
            #messages {
                height: 300px;
                padding: 10px;
                border-bottom: 1px solid #ddd;
                overflow-y: auto;
                background-color: #fafafa;
            }
            #messages p {
                margin: 5px 0;
                padding: 8px;
                border-radius: 4px;
            }
            .message-client-1 {
                background: #e1f7d5;
            }
            .message-client-2 {
                background: #d5e1f7;
            }
            .message-client-3 {
                background: #f7e1d5;
            }
            .message-client-4 {
                background: #f7d5e1;
            }
            #input-section {
                display: flex;
                padding: 10px;
                background-color: #fff;
            }
            #message {
                flex: 1;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 4px;
                margin-right: 10px;
            }
            button {
                padding: 10px 20px;
                background-color: #007bff;
                color: #fff;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            button:hover {
                background-color: #0056b3;
            }
            #metrics {
                margin-top: 20px;
                background-color: #fff;
                padding: 10px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            #metrics p {
                margin: 5px 0;
            }
        </style>
        </head>
    <body>
        <h1 style="text-align: center;">Secure Chat Room</h1>
        <div id="chat">
            <div id="messages"></div>
            <div id="username-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); display: flex; align-items: center; justify-content: center;">
                <div style="background: white; padding: 20px; border-radius: 8px; text-align: center;">
                    <h2>Enter Your Username</h2>
                    <input type="text" id="username" placeholder="Username" style="padding: 10px; margin-bottom: 10px;">
                    <br>
                    <button onclick="setUsername()" style="padding: 10px 20px;">Submit</button>
                </div>
            </div>
            <div id="input-section">
                <input type="text" id="message" placeholder="Type a message">
                <button onclick="sendMessage()">Send</button>
            </div>
        </div>
        <div id="metrics">
            <h3>Performance Metrics</h3>
            <p id="key-exchange-time">Key Exchange Time: N/A</p>
            <p id="signature-time">Digital Signature Time: N/A</p>
            <p id="encryption-time">Encryption Time: N/A</p>
            <p id="decryption-time">Decryption Time: N/A</p>
        </div>
        
        <script>
            let userName = "Anonymous";
            function setUsername() {
                const usernameInput = document.getElementById('username').value;
                if (usernameInput) {
                    userName = usernameInput;
                    socket.emit('set_username', userName);
                    document.getElementById('username-modal').style.display = 'none';
                } else {
                    alert('Please enter a valid username.');
                }
            }

            const EC = elliptic.ec;
            const ec = new EC('secp256k1');
            const socket = io();

            // Generate ECDSA key pair
            const myKey = ec.genKeyPair();
            let sharedSecrets = {}; // Store shared secrets for each client

            socket.on('connect', () => {
                const startTime = performance.now();
                // Send public key upon connecting
                socket.emit('exchange_public_key', myKey.getPublic().encodeCompressed('hex'));
                console.log('Connected to server, public key sent:', myKey.getPublic().encodeCompressed('hex'));

                // Request all connected clients' public keys
                socket.emit('request_all_public_keys');
                const endTime = performance.now();
                document.getElementById('key-exchange-time').innerText = `Key Exchange Time: ${(endTime - startTime).toFixed(2)} ms`;
            });
            
            socket.on('remove_shared_secret', (data) => {
                const { publicKeyHex } = data;
                if (sharedSecrets[publicKeyHex]) {
                    delete sharedSecrets[publicKeyHex];
                    console.log('Removed shared secret for disconnected client:', publicKeyHex);
                }
            });
                
            socket.on('exchange_public_key', (publicKeyHex) => {
                // When receiving a public key from another client
                if (publicKeyHex && publicKeyHex !== myKey.getPublic().encodeCompressed('hex')) {
                    console.log('Received public key from another client:', publicKeyHex);
                    if (!sharedSecrets[publicKeyHex]) {
                        const startTime = performance.now();
                        const otherKey = ec.keyFromPublic(publicKeyHex, 'hex');
                        sharedSecrets[publicKeyHex] = myKey.derive(otherKey.getPublic()).toString(16);
                        const endTime = performance.now();
                        console.log('Shared secret derived successfully for client:', publicKeyHex);
                        document.getElementById('key-exchange-time').innerText = `Key Exchange Time: ${(endTime - startTime).toFixed(2)} ms`;
                    }
                }
            });
            
            socket.on('receive_message', (data) => {
                // Verify the signature
                const { encryptedMessage, senderPublicKey, iv, signature, userName } = data;
                const otherKey = ec.keyFromPublic(senderPublicKey, 'hex');
                const signatureStartTime = performance.now();
                const isValidSignature = otherKey.verify(encryptedMessage, signature);
                const signatureEndTime = performance.now();
                document.getElementById('signature-time').innerText = `Digital Signature Time: ${(signatureEndTime - signatureStartTime).toFixed(2)} ms`;

                if (isValidSignature && sharedSecrets[senderPublicKey]) {
                    console.log('Decrypting message from client:', senderPublicKey);
                    try {
                        const decryptionStartTime = performance.now();
                        const encrypted = CryptoJS.enc.Base64.parse(encryptedMessage);
                        const key = CryptoJS.enc.Hex.parse(sharedSecrets[senderPublicKey].slice(0, 32)); // Use first 32 hex chars (128 bits)
                        const decrypted = CryptoJS.AES.decrypt({ ciphertext: encrypted }, key, { iv: CryptoJS.enc.Hex.parse(iv) });
                        const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
                        const decryptionEndTime = performance.now();
                        document.getElementById('decryption-time').innerText = `Decryption Time: ${(decryptionEndTime - decryptionStartTime).toFixed(2)} ms`;
                        const senderClientClass = `message-client-${Object.keys(sharedSecrets).indexOf(senderPublicKey) + 1}`;
                        document.getElementById('messages').innerHTML += `<p class="${senderClientClass}"><strong>${userName}:</strong> ${plaintext}</p>`;
                    } catch (error) {
                        console.error('Decryption failed:', error);
                    }
                } else {
                    console.log('Invalid signature or shared key is not yet established for this client. Cannot decrypt message.');
                }
            });

            function sendMessage() {
                const message = document.getElementById('message').value;
                if (!message) {
                    alert("Message is empty.");
                    return;
                }
                if (Object.keys(sharedSecrets).length === 0) {
                    console.log("No shared keys are established. Please wait until the key exchange is complete.");
                    return;
                }

                // Encrypt message for each connected client
                for (const [publicKeyHex, secret] of Object.entries(sharedSecrets)) {
                    const encryptionStartTime = performance.now();
                    const key = CryptoJS.enc.Hex.parse(secret.slice(0, 32)); // First 32 hex chars
                    const iv = CryptoJS.lib.WordArray.random(16);
                    const encrypted = CryptoJS.AES.encrypt(message, key, { iv: iv }).ciphertext;
                    const encryptedBase64 = CryptoJS.enc.Base64.stringify(encrypted);
                    const encryptionEndTime = performance.now();
                    document.getElementById('encryption-time').innerText = `Encryption Time: ${(encryptionEndTime - encryptionStartTime).toFixed(2)} ms`;

                    // Sign the encrypted message
                    const signatureStartTime = performance.now();
                    const signature = myKey.sign(encryptedBase64).toDER('hex');
                    const signatureEndTime = performance.now();
                    document.getElementById('signature-time').innerText = `Digital Signature Time: ${(signatureEndTime - signatureStartTime).toFixed(2)} ms`;

                    // Emit encrypted message to the server along with the target public key and signature
                    if (userName !== "Anonymous") {
                        socket.emit('send_message', { encryptedMessage: encryptedBase64, senderPublicKey: myKey.getPublic().encodeCompressed('hex'), targetPublicKey: publicKeyHex, userName: userName, iv: CryptoJS.enc.Hex.stringify(iv), signature: signature });
                    } else {
                        alert('Please set your username before sending messages.');
                    }
                }
                const clientClass = `message-client-${Object.keys(sharedSecrets).indexOf(myKey.getPublic().encodeCompressed('hex')) + 1}`;
                document.getElementById('messages').innerHTML += `<p class="${clientClass}"><strong>${userName}:</strong> ${message}</p>`;
                document.getElementById('message').value = '';
            }
        </script>
    </body>
    </html>
    '''

@socketio.on('send_message')
def handle_send_message(data):
    target_public_key = data.get('targetPublicKey')
    for session_id, public_key in connected_clients.items():
        if public_key == target_public_key:
            emit('receive_message', data, room=session_id)

@socketio.on('exchange_public_key')
def handle_exchange_public_key(public_key_hex):
    session_id = request.sid
    # Store the public key of the connected client by session ID
    connected_clients[session_id] = public_key_hex
    # Store the public key of the connected client
    
    # Broadcast the received public key to all clients
    emit('exchange_public_key', public_key_hex, broadcast=True, include_self=False)

@socketio.on('request_all_public_keys')
def handle_request_all_public_keys():
    # Send all stored public keys to the newly connected client
    for public_key in connected_clients.values():
        emit('exchange_public_key', public_key)

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    # Remove the disconnected client's public key from the list
    if session_id in connected_clients:
        disconnected_public_key = connected_clients[session_id]
        del connected_clients[session_id]
        # Notify clients to remove the disconnected client's key from shared secrets
        socketio.emit('remove_shared_secret', {'publicKeyHex': disconnected_public_key})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
