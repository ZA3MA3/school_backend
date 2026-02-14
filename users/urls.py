from django.urls import path
from .views import LoginView, LogoutView, CurrentUserView, RefreshTokenView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
]
