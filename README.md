# Digital Inheritance Vault: working prototype 

## Run
    pip install -r requirements.txt
    python app.py            # then open http://localhost:8000

(Use http://localhost or https://. Browser encryption needs a secure context.)
Data lives in ./data (vault.db + encrypted files). Delete that folder to reset.

## What it does
- Create vault / sign in: each user has their own account; their records are saved and available at every sign-in.
- Add records by field: bank, insurance, investments, online accounts, property, legal papers, memories, other.
  Each has its own basic-details form, a trusted-contact field, and document upload (drag & drop, 15 MB each).
- View, preview (images/PDF), download, edit and delete records.
- Activity log of every sign-in, failed attempt, upload and file access.

## How encryption works (zero-knowledge)
1. Password -> PBKDF2-SHA256 (600,000 rounds) -> 512 bits, done in the browser.
2. First 256 bits = login proof sent to the server (server stores only a scrypt hash of it).
   Last 256 bits = wrap key, never sent anywhere.
3. A random AES-256 master key is made at sign-up, wrapped (AES-GCM) with the wrap key and stored.
4. Record details, file names, categories and file bytes are encrypted in the browser with AES-256-GCM
   (fresh random IV each time) BEFORE upload. The server and database hold only ciphertext.
5. The decrypted master key lives only in browser memory (non-extractable) and is dropped on sign-out
   or after 15 minutes idle.

## Prototype limits (be honest in the demo)
- No password recovery: forgetting the password loses the data. That is the price of real encryption.
- Not yet built from the deck: trusted-contact claim flow, Shamir shared key, proof verification/OCR/ML, MFA, TLS.
  Put it behind HTTPS before any real use.
- Server can see metadata: email, number/size of items and files, timestamps.
