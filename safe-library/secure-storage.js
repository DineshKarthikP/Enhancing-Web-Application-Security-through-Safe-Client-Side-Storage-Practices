// SecureStorage library — AES-GCM + PBKDF2 with auto-expiry cleanup

const SecureStorage = (function () {
  const STORAGE_PREFIX = "ssw_v2::";
  const SALT_KEY = STORAGE_PREFIX + "salt";
  let cryptoKey = null;
  const scheduledTimers = new Map();
  let periodicCleanupId = null;
  const DEFAULT_CLEANUP_INTERVAL = 60;

  function buf2base64(buf) {
    const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf);
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  function base642buf(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = binary.charCodeAt(i);
    return arr.buffer;
  }

  async function deriveKeyFromPassphrase(passphrase, salt) {
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt instanceof ArrayBuffer ? new Uint8Array(salt) : salt, iterations: 150000, hash: "SHA-256" },
      passKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function init({ passphrase } = {}, options = {}) {
    if (!passphrase) throw new Error("Passphrase required");
    if (!window?.crypto?.subtle) throw new Error("Web Crypto API not available.");

    const autoCleanup = options.autoCleanup !== undefined ? options.autoCleanup : true;
    const cleanupIntervalSeconds = options.cleanupIntervalSeconds || DEFAULT_CLEANUP_INTERVAL;

    let salt;
    const savedSaltB64 = localStorage.getItem(SALT_KEY);
    if (savedSaltB64) salt = new Uint8Array(base642buf(savedSaltB64));
    else {
      salt = crypto.getRandomValues(new Uint8Array(16));
      localStorage.setItem(SALT_KEY, buf2base64(salt.buffer));
    }
    cryptoKey = await deriveKeyFromPassphrase(passphrase, salt);

    _clearAllScheduledTimers();
    _scanAndScheduleExpiries();

    if (autoCleanup) {
      if (periodicCleanupId) clearInterval(periodicCleanupId);
      periodicCleanupId = setInterval(() => _scanAndScheduleExpiries(), cleanupIntervalSeconds * 1000);
    }

    return { saltB64: buf2base64(salt.buffer) };
  }

  function _clearScheduledTimerForStorageKey(storageKey) {
    const t = scheduledTimers.get(storageKey);
    if (t != null) {
      clearTimeout(t);
      scheduledTimers.delete(storageKey);
    }
  }

  function _clearAllScheduledTimers() {
    for (const [k, tid] of scheduledTimers) clearTimeout(tid);
    scheduledTimers.clear();
    if (periodicCleanupId) {
      clearInterval(periodicCleanupId);
      periodicCleanupId = null;
    }
  }

  function _scheduleDeletion(storageKey, expiryAt) {
    _clearScheduledTimerForStorageKey(storageKey);
    if (!expiryAt || Date.now() >= expiryAt) {
      localStorage.removeItem(storageKey);
      return;
    }

    let ms = Math.max(0, expiryAt - Date.now());
    const MAX_TIMEOUT = 2147483647;
    if (ms > MAX_TIMEOUT) {
      const tid = setTimeout(() => {
        const raw = localStorage.getItem(storageKey);
        if (!raw) return _clearScheduledTimerForStorageKey(storageKey);
        try {
          const meta = JSON.parse(raw);
          if (!meta.expiry) return _clearScheduledTimerForStorageKey(storageKey);
          _scheduleDeletion(storageKey, meta.expiry);
        } catch {
          localStorage.removeItem(storageKey);
          _clearScheduledTimerForStorageKey(storageKey);
        }
      }, MAX_TIMEOUT);
      scheduledTimers.set(storageKey, tid);
    } else {
      const tid = setTimeout(() => {
        localStorage.removeItem(storageKey);
        scheduledTimers.delete(storageKey);
      }, ms);
      scheduledTimers.set(storageKey, tid);
    }
  }

  function _scanAndScheduleExpiries() {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (!k || !k.startsWith(STORAGE_PREFIX)) continue;
      try {
        const raw = localStorage.getItem(k);
        if (!raw) continue;
        const meta = JSON.parse(raw);
        if (!meta || typeof meta !== "object") {
          localStorage.removeItem(k);
          continue;
        }
        if (meta.expiry && Date.now() >= meta.expiry) {
          localStorage.removeItem(k);
        } else if (meta.expiry) {
          _scheduleDeletion(k, meta.expiry);
        }
      } catch {
        localStorage.removeItem(k);
      }
    }
  }

  async function encryptRaw(plainText) {
    if (!cryptoKey) throw new Error("Not initialized. Call init({passphrase}).");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, enc.encode(plainText));
    return { cipherB64: buf2base64(cipher), ivB64: buf2base64(iv.buffer) };
  }

  async function decryptRaw(cipherB64, ivB64) {
    if (!cryptoKey) throw new Error("Not initialized. Call init({passphrase}).");
    const cipherBuf = base642buf(cipherB64);
    const ivBuf = base642buf(ivB64);
    try {
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, cryptoKey, cipherBuf);
      return new TextDecoder().decode(plainBuf);
    } catch {
      return null;
    }
  }

  function storageKey(key) { return STORAGE_PREFIX + key; }

  async function setItem(key, value, expirySeconds = null) {
    const payload = typeof value === "string" ? value : JSON.stringify(value);
    const { cipherB64, ivB64 } = await encryptRaw(payload);
    const expiry = expirySeconds ? Date.now() + expirySeconds * 1000 : null;
    const meta = { cipher: cipherB64, iv: ivB64, createdAt: Date.now(), expiry };
    const sKey = storageKey(key);
    localStorage.setItem(sKey, JSON.stringify(meta));
    if (expiry) _scheduleDeletion(sKey, expiry);
    return true;
  }

  async function getItem(key) {
    const raw = localStorage.getItem(storageKey(key));
    if (!raw) return null;
    try {
      const meta = JSON.parse(raw);
      if (meta.expiry && Date.now() > meta.expiry) {
        localStorage.removeItem(storageKey(key));
        return null;
      }
      const plain = await decryptRaw(meta.cipher, meta.iv);
      return plain ? JSON.parse(plain) : null;
    } catch {
      return null;
    }
  }

  function removeItem(key) { localStorage.removeItem(storageKey(key)); }
  function clear() {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.startsWith(STORAGE_PREFIX)) localStorage.removeItem(k);
    }
    localStorage.removeItem(SALT_KEY);
    cryptoKey = null;
  }

  return { init, setItem, getItem, removeItem, clear };
})();

export default SecureStorage;
