from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import base64
import os
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
import secrets

def home(request):
    return render(request, 'encryption_app/index.html')

@csrf_exempt
def encrypt_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            method = data.get('method')
            plaintext = data.get('plaintext')
            key = data.get('key')

            if not all([method, plaintext, key]):
                return JsonResponse({'error': 'Missing required parameters'}, status=400)

            if method == 'aes':
                result = aes_encrypt(plaintext, key)
            elif method == 'tripledes':
                result = triple_des_encrypt(plaintext, key)
            elif method == 'otp':
                result = otp_encrypt(plaintext, key)
            else:
                return JsonResponse({'error': 'Invalid encryption method'}, status=400)

            return JsonResponse({'result': result})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def decrypt_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            method = data.get('method')
            ciphertext = data.get('ciphertext')
            key = data.get('key')

            if not all([method, ciphertext, key]):
                return JsonResponse({'error': 'Missing required parameters'}, status=400)

            if method == 'aes':
                result = aes_decrypt(ciphertext, key)
            elif method == 'tripledes':
                result = triple_des_decrypt(ciphertext, key)
            elif method == 'otp':
                result = otp_decrypt(ciphertext, key)
            else:
                return JsonResponse({'error': 'Invalid decryption method'}, status=400)

            return JsonResponse({'result': result})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

def generate_key(request):
    try:
        length = int(request.GET.get('length', 16))
        if length > 64:
            length = 64

        random_key = secrets.token_hex(length)

        return JsonResponse({'key': random_key})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def aes_encrypt(plaintext, key):
    from hashlib import sha256
    key_bytes = sha256(key.encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def aes_decrypt(ciphertext, key):
    from hashlib import sha256
    key_bytes = sha256(key.encode()).digest()
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv = ciphertext_bytes[:16]
    encrypted_data = ciphertext_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    data = unpad(padded_data, AES.block_size)
    return data.decode('utf-8')

def triple_des_encrypt(plaintext, key):
    from hashlib import md5
    key_bytes = md5(key.encode()).digest() + md5((key + "salt").encode()).digest()[:8]
    iv = os.urandom(8)
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), DES3.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def triple_des_decrypt(ciphertext, key):
    from hashlib import md5
    key_bytes = md5(key.encode()).digest() + md5((key + "salt").encode()).digest()[:8]
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv = ciphertext_bytes[:8]
    encrypted_data = ciphertext_bytes[8:]
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    data = unpad(padded_data, DES3.block_size)
    return data.decode('utf-8')

def otp_encrypt(plaintext, key):
    if len(key) < len(plaintext):
        raise ValueError("OTP key must be at least as long as the plaintext")
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        ciphertext.append(ord(plaintext[i]) ^ ord(key[i]))
    return base64.b64encode(ciphertext).decode('utf-8')

def otp_decrypt(ciphertext, key):
    ciphertext_bytes = base64.b64decode(ciphertext)
    if len(key) < len(ciphertext_bytes):
        raise ValueError("OTP key must be at least as long as the ciphertext")
    plaintext = ''
    for i in range(len(ciphertext_bytes)):
        plaintext += chr(ciphertext_bytes[i] ^ ord(key[i]))
    return plaintext