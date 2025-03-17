from django.shortcuts import render, redirect
from django.contrib.auth import login
from .models import CustomUser
from .utils import generate_otp, verify_otp
from django.core.mail import send_mail
from django.conf import settings

def home(request):
    return redirect('register')  # Redirect to the registration page

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        mobile_number = request.POST['mobile_number']
        password = request.POST['password']

        user = CustomUser.objects.create_user(username=username, email=email, 
                                              mobile_number=mobile_number, password=password)

        # Generate and save OTPs
        email_otp = generate_otp()
        mobile_otp = generate_otp()
        user.email_otp = email_otp
        user.mobile_otp = mobile_otp
        user.save()

        # Send email OTP
        send_mail(
            'Email Verification OTP',
            f'Your OTP for email verification is: {email_otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        # Send mobile OTP (you'll need to integrate with an SMS service)
        # For this example, we'll just print it
        print(f"Mobile OTP: {mobile_otp}")

        return redirect('verify_otp', user_id=user.id)

    return render(request, 'user_auth/register.html')

def verify_otp(request, user_id):
    user = CustomUser.objects.get(id=user_id)

    if request.method == 'POST':
        email_otp = request.POST['email_otp']
        mobile_otp = request.POST['mobile_otp']

        if verify_otp(email_otp, user.email_otp) and verify_otp(mobile_otp, user.mobile_otp):
            user.is_email_verified = True
            user.is_mobile_verified = True
            user.email_otp = None
            user.mobile_otp = None
            user.save()
            login(request, user)
            return redirect('home')  # Redirect to home page after successful verification
        else:
            return render(request, 'user_auth/verify_otp.html', {'error': 'Invalid OTP'})

    return render(request, 'user_auth/verify_otp.html')