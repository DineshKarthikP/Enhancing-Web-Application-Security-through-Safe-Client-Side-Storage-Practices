# 🛡️ Enhancing Web Application Security through Safe Client-Side Storage Practices

This repository demonstrates a **secure approach to storing and retrieving sensitive data** (like authentication tokens, profile data, or session information) on the **client side** of a web application.  
It contrasts **insecure storage practices** with a **secure, wrapper-based design**, supported by a clean modular implementation and visual workflow.

---

## 📌 Why This Matters

Storing data directly in `localStorage` or `sessionStorage` without encryption exposes it to attacks such as:

| Threat | Description |
|--------|--------------|
| ⚠️ **Cross-Site Scripting (XSS)** | Malicious scripts can read and exfiltrate tokens. |
| 🔑 **Session Hijacking** | Compromised tokens allow unauthorized access. |
| 🧩 **Data Tampering / Loss** | Raw values can be modified, deleted, or corrupted. |

The secure design mitigates these issues by enforcing **encryption**, **expiry validation**, and **structured payloads** before data is stored or retrieved.

---

## 🔑 Workflow Overview

### ❌ Insecure Flow
1. Directly store raw values in `localStorage`.
2. Data remains unencrypted and visible to scripts.
3. Retrieval may return manipulated or stolen data.

```js
// Insecure example
localStorage.setItem("token", "abcdef12345");
const token = localStorage.getItem("token"); // exposed to any script
````

---

### ✅ Secure Flow

1. Use a secure wrapper (`setItem`, `getItem`) for all storage operations.
2. Encrypt data using AES-GCM with PBKDF2-derived keys.
3. Store encrypted JSON payloads with metadata (IV, salt, expiry).
4. On retrieval:

   * Validate expiry.
   * Decrypt safely.
   * Return only valid data.
5. If invalid or expired → securely delete and return `null`.

```js
// Secure example using Safe Library
import safeLibrary from "safe-library";
const { SecureStorage } = safeLibrary;

await SecureStorage.init({ passphrase: "mySecretKey" });
await SecureStorage.setItem("authToken", { token: "abcdef12345" }, 3600); // expires in 1 hour

const tokenData = await SecureStorage.getItem("authToken");
console.log(tokenData); // decrypted object or null if expired
```

---

## 🧩 Features of the Secure Wrapper

| Feature                   | Description                                          |
| ------------------------- | ---------------------------------------------------- |
| 🔒 **Transparent API**    | Works just like `localStorage`, but securely.        |
| 🧠 **AES-GCM Encryption** | Data is encrypted before being stored.               |
| ⏱ **Auto-Expiry**         | Prevents indefinite persistence of sensitive tokens. |
| 🧹 **Auto Cleanup**       | Expired items are deleted automatically.             |
| ⚙️ **Error Handling**     | Gracefully handles corrupted or invalid payloads.    |

---

## 🏗️ Project Structure

```
safe-website/
├── login.html                # Secure login demo UI
└── safe-library/
    ├── index.js              # Library entry point
    └── secure-storage.js     # Core encryption + secure storage logic
```

### 🔸 `safe-library/secure-storage.js`

* Core logic implementing AES-GCM encryption + PBKDF2 key derivation.
* Provides methods:

  ```js
  SecureStorage.init({ passphrase })
  SecureStorage.setItem(key, value, expirySeconds)
  SecureStorage.getItem(key)
  SecureStorage.removeItem(key)
  SecureStorage.clear()
  ```
* Automatically handles expiry and periodic cleanup.

### 🔸 `safe-library/index.js`

* Entry point of the library that re-exports all secure features.
* Enables modular import like:

  ```js
  import safeLibrary from "safe-library";
  const { SecureStorage } = safeLibrary;
  ```

### 🔸 `login.html`

* Frontend interface that demonstrates:

  * Securely saving credentials.
  * Viewing decrypted data.
  * Clearing stored encrypted data.
* Uses import maps to simulate:

  ```js
  import safeLibrary from "safe-library";
  ```

---

## 🚀 Getting Started

### 1️⃣ Clone the repository

```bash
git clone https://github.com/yourusername/secure-storage-workflow.git
cd secure-storage-workflow
```

### 2️⃣ Run a local server

ES modules require HTTP/HTTPS context — not `file://`.

Using Python:

```bash
python3 -m http.server 8080
```

Using Node.js:

```bash
npx http-server .
```

Then open:

```
http://localhost:8080/login.html
```

---

## 🧠 Educational Goal

This project demonstrates **how to design secure client-side data workflows**
that protect users even if an attacker gains JavaScript execution capabilities.

It is ideal for:

* Web developers learning **Web Crypto API**
* Students exploring **secure frontend architectures**
* Teams implementing **token-based authentication in SPAs**

---

## ⚙️ Technologies Used

* **Web Crypto API (AES-GCM, PBKDF2)**
* **Vanilla JavaScript (ES Modules + Import Maps)**
* **LocalStorage API**
* **HTML5 UI**
* **Python/Node.js local server for testing**

---
