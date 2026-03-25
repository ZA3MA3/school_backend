from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser


class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that reads tokens from HttpOnly cookies.
    """
    
    def authenticate(self, request):
        # Get the token from the cookie first
        access_token = request.COOKIES.get('access_token')
        
        if access_token:
            try:
                validated_token = self.get_validated_token(access_token)
                return self.get_user(validated_token), validated_token
            except (InvalidToken, TokenError):
                # If the access token is invalid, try to refresh it
                refresh_token = request.COOKIES.get('refresh_token')
                if refresh_token:
                    return self._refresh_token(request, refresh_token)
                return None
        
        # Fall back to the parent class behavior (for Authorization header)
        return super().authenticate(request)
    
    def _refresh_token(self, request, refresh_token):
        from rest_framework_simplejwt.tokens import RefreshToken
        from django.http import JsonResponse
        
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            # Return the user and token
            user = self.get_user(refresh)
            validated_token = self.get_validated_token(access_token)
            
            # Store the new access token in the request for the view to use
            request.new_access_token = access_token
            
            return user, validated_token
            
        except (InvalidToken, TokenError):
            return None
