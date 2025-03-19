from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('api/encrypt/', views.encrypt_api, name='encrypt_api'),
    path('api/decrypt/', views.decrypt_api, name='decrypt_api'),
    path('api/generate_key/', views.generate_key, name='generate_key'),
]