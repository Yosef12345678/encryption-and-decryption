from django.urls import path
from . import views

app_name = 'encryption_app'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/rsa/encrypt/', views.encrypt_rsa, name='encrypt_rsa'),
    path('api/rsa/decrypt/', views.decrypt_rsa, name='decrypt_rsa'),
]