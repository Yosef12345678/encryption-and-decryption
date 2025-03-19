// Initialize variables and elements
const encryptionMethodSelect = document.getElementById('encryption-method');
const methodInfo = document.getElementById('method-info');
const keyContainer = document.getElementById('key-container');
let keyInput = document.getElementById('key');
const plaintextInput = document.getElementById('plaintext');
const ciphertextInput = document.getElementById('ciphertext');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const resultContainer = document.getElementById('result-container');
const resultText = document.getElementById('result-text');
const loading = document.getElementById('loading');
const generateKeyBtn = document.getElementById('generate-key-btn');

// Method information descriptions
const methodInfoText = {
    'aes': 'AES is a symmetric encryption algorithm widely used for secure data transmission.',
    'tripledes': 'Triple DES applies the DES cipher algorithm three times to each data block for enhanced security.',
    'otp': 'One-Time Pad is a theoretically unbreakable encryption technique that uses a random key the same length as the message.'
};

// Event listeners
encryptionMethodSelect.addEventListener('change', updateMethodInfo);
encryptBtn.addEventListener('click', encrypt);
decryptBtn.addEventListener('click', decrypt);
generateKeyBtn.addEventListener('click', generateKey);

// Update method information when selection changes
function updateMethodInfo() {
    const selectedMethod = encryptionMethodSelect.value;
    methodInfo.textContent = methodInfoText[selectedMethod];
    
    // Add note about OTP key length when OTP is selected
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

// Generate a random encryption key
function generateKey() {
    const method = encryptionMethodSelect.value;
    let length = 16; // Default length for AES and Triple DES
    
    if (method === 'otp') {
        // For OTP, get the length from the plaintext
        const plaintext = plaintextInput.value.trim();
        if (!plaintext) {
            alert('Please enter plaintext first to generate a matching OTP key');
            return;
        }
        length = plaintext.length;
    }
    
    // Client-side key generation
    if (method === 'otp') {
        // For OTP, generate a random string of the same length as plaintext
        let key = '';
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            key += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        keyInput.value = key;
    } else {
        // For AES/3DES, generate a hex string
        let key = '';
        const characters = '0123456789abcdef';
        const charactersLength = characters.length;
        for (let i = 0; i < 32; i++) {
            key += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        keyInput.value = key;
    }
}

// Show loading spinner
function showLoading() {
    loading.style.display = 'block';
    resultContainer.style.display = 'none';
}

// Hide loading spinner
function hideLoading() {
    loading.style.display = 'none';
}

// Show result
function showResult(text) {
    resultText.textContent = text;
    resultContainer.style.display = 'block';
    hideLoading();
}

// ENCRYPTION FUNCTIONS

// Client-side AES encryption
function aesEncrypt(plaintext, key) {
    try {
        const encrypted = CryptoJS.AES.encrypt(plaintext, key).toString();
        return encrypted;
    } catch (error) {
        throw new Error('AES encryption failed: ' + error.message);
    }
}

// Client-side AES decryption
function aesDecrypt(ciphertext, key) {
    try {
        const decrypted = CryptoJS.AES.decrypt(ciphertext, key);
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        throw new Error('AES decryption failed: ' + error.message);
    }
}

// Client-side Triple DES encryption
function tripleDesEncrypt(plaintext, key) {
    try {
        const encrypted = CryptoJS.TripleDES.encrypt(plaintext, key).toString();
        return encrypted;
    } catch (error) {
        throw new Error('Triple DES encryption failed: ' + error.message);
    }
}

// Client-side Triple DES decryption
function tripleDesDecrypt(ciphertext, key) {
    try {
        const decrypted = CryptoJS.TripleDES.decrypt(ciphertext, key);
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        throw new Error('Triple DES decryption failed: ' + error.message);
    }
}

// Client-side OTP encryption
function otpEncrypt(plaintext, key) {
    try {
        if (key.length !== plaintext.length) {
            throw new Error('OTP key must be the same length as the plaintext');
        }
        
        let result = '';
        for (let i = 0; i < plaintext.length; i++) {
            // XOR the character codes and convert back to character
            const charCode = plaintext.charCodeAt(i) ^ key.charCodeAt(i);
            result += String.fromCharCode(charCode);
        }
        
        // Convert to Base64 for better display
        return btoa(result);
    } catch (error) {
        throw new Error('OTP encryption failed: ' + error.message);
    }
}

// Client-side OTP decryption
function otpDecrypt(ciphertext, key) {
    try {
        // Decode from Base64
        const decoded = atob(ciphertext);
        
        if (key.length !== decoded.length) {
            throw new Error('OTP key must be the same length as the decoded ciphertext');
        }
        
        let result = '';
        for (let i = 0; i < decoded.length; i++) {
            // XOR the character codes and convert back to character
            const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i);
            result += String.fromCharCode(charCode);
        }
        
        return result;
    } catch (error) {
        throw new Error('OTP decryption failed: ' + error.message);
    }
}

// Encrypt function
function encrypt() {
    const method = encryptionMethodSelect.value;
    const plaintext = plaintextInput.value.trim();
    const key = keyInput.value;
    
    if (!plaintext) {
        alert('Please enter text to encrypt');
        return;
    }
    
    if (!key) {
        alert('Please enter an encryption key');
        return;
    }
    
    showLoading();
    
    // Client-side encryption
    setTimeout(() => {
        try {
            let result;
            
            switch (method) {
                case 'aes':
                    result = aesEncrypt(plaintext, key);
                    break;
                case 'tripledes':
                    result = tripleDesEncrypt(plaintext, key);
                    break;
                case 'otp':
                    result = otpEncrypt(plaintext, key);
                    break;
                default:
                    throw new Error('Invalid encryption method selected');
            }
            
            ciphertextInput.value = result;
            showResult('Encryption successful');
        } catch (error) {
            showResult('Error: ' + error.message);
        }
    }, 300);
}

// Decrypt function
function decrypt() {
    const method = encryptionMethodSelect.value;
    const ciphertext = ciphertextInput.value.trim();
    const key = keyInput.value;
    
    if (!ciphertext) {
        alert('Please enter text to decrypt');
        return;
    }
    
    if (!key) {
        alert('Please enter a decryption key');
        return;
    }
    
    showLoading();
    
    // Client-side decryption
    setTimeout(() => {
        try {
            let result;
            
            switch (method) {
                case 'aes':
                    result = aesDecrypt(ciphertext, key);
                    break;
                case 'tripledes':
                    result = tripleDesDecrypt(ciphertext, key);
                    break;
                case 'otp':
                    result = otpDecrypt(ciphertext, key);
                    break;
                default:
                    throw new Error('Invalid decryption method selected');
            }
            
            if (!result) {
                throw new Error('Decryption failed. Invalid key or ciphertext.');
            }
            
            plaintextInput.value = result;
            showResult('Decryption successful');
        } catch (error) {
            showResult('Error: ' + error.message);
        }
    }, 300);
}

// Initialize the page
updateMethodInfo();

// Check for dark mode preference
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