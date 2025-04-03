from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import traceback
from .utils import rsa_encrypt, rsa_decrypt

def index(request):
    """
    View function for the encryption tools home page.
    """
    return render(request, 'encryption_app/index.html')

@csrf_exempt
def encrypt_rsa(request):
    """API view for RSA encryption"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            plaintext = data.get('plaintext', '')
            public_key = data.get('public_key', '')
            
            if not plaintext or not public_key:
                return JsonResponse({
                    'success': False, 
                    'error': 'Both plaintext and public key are required'
                })
            
            encrypted = rsa_encrypt(public_key, plaintext)
            return JsonResponse({'success': True, 'ciphertext': encrypted})
        except Exception as e:
            print(f"RSA Encryption error: {str(e)}")
            print(traceback.format_exc())
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})

@csrf_exempt
def decrypt_rsa(request):
    """API view for RSA decryption"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ciphertext = data.get('ciphertext', '')
            private_key = data.get('private_key', '')
            
            if not ciphertext or not private_key:
                return JsonResponse({
                    'success': False, 
                    'error': 'Both ciphertext and private key are required'
                })
            
            decrypted = rsa_decrypt(private_key, ciphertext)
            return JsonResponse({'success': True, 'plaintext': decrypted})
        except Exception as e:
            print(f"RSA Decryption error: {str(e)}")
            print(traceback.format_exc())
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'})