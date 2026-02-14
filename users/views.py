from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.conf import settings
from .serializers import LoginSerializer
from .models import User


class LoginView(APIView):
    """
    Login endpoint that sets JWT token in HttpOnly cookie.
    """
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Create response with user data
            response = Response({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email if hasattr(user, 'email') else None,
                    'first_name': user.first_name if hasattr(user, 'first_name') else None,
                    'last_name': user.last_name if hasattr(user, 'last_name') else None,
                },
                'role': user.role
            })
            
            # Set HttpOnly cookies
            # Access token cookie
            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=not settings.DEBUG,  # Secure in production
                samesite='Lax',
                max_age=3600,  # 1 hour
                path='/'
            )
            
            # Refresh token cookie
            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=7 * 24 * 3600,  # 7 days
                path='/'
            )
            
            return response
        else:
            return Response(
                {'detail': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )







class LogoutView(APIView):
    """
    Logout endpoint that clears JWT cookies.
    """
    permission_classes = []
    authentication_classes = []
    def post(self, request):
        response = Response({'detail': 'Successfully logged out'})
        
        # Delete cookies
        response.delete_cookie('access_token', path='/')
        response.delete_cookie('refresh_token', path='/')
        
        return response


class CurrentUserView(APIView):
    """
    Get current authenticated user information.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email if hasattr(user, 'email') else None,
            'first_name': user.first_name if hasattr(user, 'first_name') else None,
            'last_name': user.last_name if hasattr(user, 'last_name') else None,
            'role': user.role
        })


class RefreshTokenView(APIView):
    """
    Refresh access token using refresh token from cookie.
    """
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return Response(
                {'detail': 'Refresh token not found'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            response = Response({'detail': 'Token refreshed'})
            
            # Set new access token cookie
            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=3600,
                path='/'
            )
            
            return response
            
        except TokenError:
            return Response(
                {'detail': 'Invalid or expired refresh token'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
