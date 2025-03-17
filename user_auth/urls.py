from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),  # Registration page
    path('verify_otp/<int:user_id>/', views.verify_otp, name='verify_otp'),  # OTP verification
    path('', views.home, name='home'),  # Home page (root URL)
]