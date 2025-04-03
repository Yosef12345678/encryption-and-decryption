const encryptionMethodSelect = document.getElementById('encryption-method');
const methodInfo = document.getElementById('method-info');
const keyContainer = document.getElementById('key-container');
const rsaKeyContainer = document.getElementById('rsa-key-container');
const serverRsaKeyContainer = document.getElementById('server-rsa-key-container');
let keyInput = document.getElementById('key');
const plaintextInput = document.getElementById('plaintext');
const ciphertextInput = document.getElementById('ciphertext');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const resultContainer = document.getElementById('result-container');
const resultText = document.getElementById('result-text');
const loading = document.getElementById('loading');
const generateKeyBtn = document.getElementById('generate-key-btn');
const publicKeyInput = document.getElementById('public-key');
const privateKeyInput = document.getElementById('private-key');
const generateRsaKeysBtn = document.getElementById('generate-rsa-keys-btn');
const serverPublicKeyInput = document.getElementById('server-public-key');
const serverPrivateKeyInput = document.getElementById('server-private-key');

const methodInfoText = {
    'aes': 'AES is a symmetric encryption algorithm widely used for secure data transmission.',
    'tripledes': 'Triple DES applies the DES cipher algorithm three times to each data block for enhanced security.',
    'otp': 'One-Time Pad is a theoretically unbreakable encryption technique that uses a random key the same length as the message.',
    'rsa': 'RSA is an asymmetric encryption algorithm that uses a pair of keys: public key for encryption and private key for decryption.',
    'rsa-server': 'Server-side RSA encryption using Python cryptography library with your own OpenSSL-generated keys.'
};

encryptionMethodSelect.addEventListener('change', updateMethodInfo);
encryptBtn.addEventListener('click', encrypt);
decryptBtn.addEventListener('click', decrypt);
generateKeyBtn && generateKeyBtn.addEventListener('click', generateKey);
generateRsaKeysBtn && generateRsaKeysBtn.addEventListener('click', generateRsaKeys);

function updateMethodInfo() {
    const selectedMethod = encryptionMethodSelect.value;
    methodInfo.textContent = methodInfoText[selectedMethod];

    // Show/hide appropriate key inputs based on the selected method
    if (selectedMethod === 'rsa') {
        keyContainer.style.display = 'none';
        rsaKeyContainer.style.display = 'block';
        serverRsaKeyContainer.style.display = 'none';
    } else if (selectedMethod === 'rsa-server') {
        keyContainer.style.display = 'none';
        rsaKeyContainer.style.display = 'none';
        serverRsaKeyContainer.style.display = 'block';
    } else {
        keyContainer.style.display = 'block';
        rsaKeyContainer.style.display = 'none';
        serverRsaKeyContainer.style.display = 'none';
        
        if (selectedMethod === 'otp') {
            keyContainer.innerHTML = `
                <label for="key">Secret Key</label>
                <input type="text" id="key" placeholder="Enter encryption key (same length as message for OTP)">
                <div class="key-actions">
                    <button id="generate-key-btn">Generate Key</button>
                </div>
                <div class="method-info">Note: For OTP, the key must be the same length as your message.</div>
            `;
        } else {
            keyContainer.innerHTML = `
                <label for="key">Secret Key</label>
                <input type="text" id="key" placeholder="Enter encryption key">
                <div class="key-actions">
                    <button id="generate-key-btn">Generate Key</button>
                </div>
            `;
        }
        keyInput = document.getElementById('key');
        document.getElementById('generate-key-btn').addEventListener('click', generateKey);
    }
}

function generateKey() {
    const method = encryptionMethodSelect.value;
    let length = 16;

    if (method === 'otp') {
        const plaintext = plaintextInput.value.trim();
        if (!plaintext) {
            alert('Please enter plaintext first to generate a matching OTP key');
            return;
        }
        length = plaintext.length;
    }

    if (method === 'otp') {
        let key = '';
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            key += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        keyInput.value = key;
    } else {
        let key = '';
        const characters = '0123456789abcdef';
        const charactersLength = characters.length;
        for (let i = 0; i < 32; i++) {
            key += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        keyInput.value = key;
    }
}

function generateRsaKeys() {
    showLoading();
    
    setTimeout(() => {
        try {
            // Create a new JSEncrypt instance
            const crypt = new JSEncrypt({default_key_size: 2048});
            
            // Generate key pair
            crypt.getKey();
            
            // Get and display the keys
            publicKeyInput.value = crypt.getPublicKey();
            privateKeyInput.value = crypt.getPrivateKey();
            
            showResult('RSA key pair generated successfully');
        } catch (error) {
            showResult('Error generating RSA keys: ' + error.message);
        } finally {
            hideLoading();
        }
    }, 500);
}

function showLoading() {
    loading.style.display = 'block';
    resultContainer.style.display = 'none';
}

function hideLoading() {
    loading.style.display = 'none';
}

function showResult(text) {
    resultText.textContent = text;
    resultContainer.style.display = 'block';
    hideLoading();
}

function aesEncrypt(plaintext, key) {
    try {
        const encrypted = CryptoJS.AES.encrypt(plaintext, key).toString();
        return encrypted;
    } catch (error) {
        throw new Error('AES encryption failed: ' + error.message);
    }
}

function aesDecrypt(ciphertext, key) {
    try {
        const decrypted = CryptoJS.AES.decrypt(ciphertext, key);
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        throw new Error('AES decryption failed: ' + error.message);
    }
}

function tripleDesEncrypt(plaintext, key) {
    try {
        const encrypted = CryptoJS.TripleDES.encrypt(plaintext, key).toString();
        return encrypted;
    } catch (error) {
        throw new Error('Triple DES encryption failed: ' + error.message);
    }
}

function tripleDesDecrypt(ciphertext, key) {
    try {
        const decrypted = CryptoJS.TripleDES.decrypt(ciphertext, key);
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        throw new Error('Triple DES decryption failed: ' + error.message);
    }
}

function otpEncrypt(plaintext, key) {
    try {
        if (key.length !== plaintext.length) {
            throw new Error('OTP key must be the same length as the plaintext');
        }

        let result = '';
        for (let i = 0; i < plaintext.length; i++) {
            const charCode = plaintext.charCodeAt(i) ^ key.charCodeAt(i);
            result += String.fromCharCode(charCode);
        }

        return btoa(result);
    } catch (error) {
        throw new Error('OTP encryption failed: ' + error.message);
    }
}

function otpDecrypt(ciphertext, key) {
    try {
        const decoded = atob(ciphertext);

        if (key.length !== decoded.length) {
            throw new Error('OTP key must be the same length as the decoded ciphertext');
        }

        let result = '';
        for (let i = 0; i < decoded.length; i++) {
            const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i);
            result += String.fromCharCode(charCode);
        }

        return result;
    } catch (error) {
        throw new Error('OTP decryption failed: ' + error.message);
    }
}

function rsaEncrypt(plaintext, publicKey) {
    try {
        if (!publicKey) {
            throw new Error('Public key is required for RSA encryption');
        }
        
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        
        // RSA has size limitations, so we need to check the input length
        if (plaintext.length > 200) {
            throw new Error('RSA encryption is limited to shorter messages (< 200 characters)');
        }
        
        const encrypted = encrypt.encrypt(plaintext);
        if (!encrypted) {
            throw new Error('RSA encryption failed. Please check your public key.');
        }
        
        return encrypted;
    } catch (error) {
        throw new Error('RSA encryption failed: ' + error.message);
    }
}

function rsaDecrypt(ciphertext, privateKey) {
    try {
        if (!privateKey) {
            throw new Error('Private key is required for RSA decryption');
        }
        
        const decrypt = new JSEncrypt();
        decrypt.setPrivateKey(privateKey);
        
        const decrypted = decrypt.decrypt(ciphertext);
        if (decrypted === null || decrypted === false) {
            throw new Error('RSA decryption failed. Please check your private key and ciphertext.');
        }
        
        return decrypted;
    } catch (error) {
        throw new Error('RSA decryption failed: ' + error.message);
    }
}

// Get CSRF token from cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

async function serverRsaEncrypt(plaintext, publicKey) {
    try {
        const csrftoken = getCookie('csrftoken');
        
        const response = await fetch('/api/rsa/encrypt/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken || '',
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                plaintext: plaintext,
                public_key: publicKey
            })
        });
        
        if (!response.ok) {
            throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Server-side RSA encryption failed');
        }
        
        return data.ciphertext;
    } catch (error) {
        console.error('Encryption fetch error:', error);
        throw new Error(`Server-side RSA encryption failed: ${error.message}`);
    }
}

async function serverRsaDecrypt(ciphertext, privateKey) {
    try {
        const csrftoken = getCookie('csrftoken');
        
        const response = await fetch('/api/rsa/decrypt/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken || '',
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                ciphertext: ciphertext,
                private_key: privateKey
            })
        });
        
        if (!response.ok) {
            throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Server-side RSA decryption failed');
        }
        
        return data.plaintext;
    } catch (error) {
        console.error('Decryption fetch error:', error);
        throw new Error(`Server-side RSA decryption failed: ${error.message}`);
    }
}

async function encrypt() {
    const method = encryptionMethodSelect.value;
    const plaintext = plaintextInput.value.trim();

    if (!plaintext) {
        alert('Please enter text to encrypt');
        return;
    }

    showLoading();

    try {
        let result;

        if (method === 'rsa-server') {
            const publicKey = serverPublicKeyInput.value;
            if (!publicKey) {
                throw new Error('Please enter an RSA public key');
            }
            result = await serverRsaEncrypt(plaintext, publicKey);
        } else {
            switch (method) {
                case 'aes':
                    const aesKey = keyInput.value;
                    if (!aesKey) {
                        throw new Error('Please enter an encryption key');
                    }
                    result = aesEncrypt(plaintext, aesKey);
                    break;
                case 'tripledes':
                    const desKey = keyInput.value;
                    if (!desKey) {
                        throw new Error('Please enter an encryption key');
                    }
                    result = tripleDesEncrypt(plaintext, desKey);
                    break;
                case 'otp':
                    const otpKey = keyInput.value;
                    if (!otpKey) {
                        throw new Error('Please enter an encryption key');
                    }
                    result = otpEncrypt(plaintext, otpKey);
                    break;
                case 'rsa':
                    const publicKey = publicKeyInput.value;
                    if (!publicKey) {
                        throw new Error('Please enter or generate an RSA public key');
                    }
                    result = rsaEncrypt(plaintext, publicKey);
                    break;
                default:
                    throw new Error('Invalid encryption method selected');
            }
        }

        ciphertextInput.value = result;
        showResult('Encryption successful');
    } catch (error) {
        showResult('Error: ' + error.message);
    } finally {
        hideLoading();
    }
}

async function decrypt() {
    const method = encryptionMethodSelect.value;
    const ciphertext = ciphertextInput.value.trim();

    if (!ciphertext) {
        alert('Please enter text to decrypt');
        return;
    }

    showLoading();

    try {
        let result;

        if (method === 'rsa-server') {
            const privateKey = serverPrivateKeyInput.value;
            if (!privateKey) {
                throw new Error('Please enter an RSA private key');
            }
            result = await serverRsaDecrypt(ciphertext, privateKey);
        } else {
            switch (method) {
                case 'aes':
                    const aesKey = keyInput.value;
                    if (!aesKey) {
                        throw new Error('Please enter a decryption key');
                    }
                    result = aesDecrypt(ciphertext, aesKey);
                    break;
                case 'tripledes':
                    const desKey = keyInput.value;
                    if (!desKey) {
                        throw new Error('Please enter a decryption key');
                    }
                    result = tripleDesDecrypt(ciphertext, desKey);
                    break;
                case 'otp':
                    const otpKey = keyInput.value;
                    if (!otpKey) {
                        throw new Error('Please enter a decryption key');
                    }
                    result = otpDecrypt(ciphertext, otpKey);
                    break;
                case 'rsa':
                    const privateKey = privateKeyInput.value;
                    if (!privateKey) {
                        throw new Error('Please enter or generate an RSA private key');
                    }
                    result = rsaDecrypt(ciphertext, privateKey);
                    break;
                default:
                    throw new Error('Invalid decryption method selected');
            }
        }

        if (!result) {
            throw new Error('Decryption failed. Invalid key or ciphertext.');
        }

        plaintextInput.value = result;
        showResult('Decryption successful');
    } catch (error) {
        showResult('Error: ' + error.message);
    } finally {
        hideLoading();
    }
}

updateMethodInfo();

if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.classList.add('dark');
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
    if (event.matches) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
});