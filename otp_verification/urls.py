from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),  # Django admin panel
    path('', include('user_auth.urls')),  # Include user_auth URLs at the root level
]