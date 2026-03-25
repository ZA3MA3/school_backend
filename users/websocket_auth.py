import logging
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError

logger = logging.getLogger(__name__)
User = get_user_model()


@database_sync_to_async
def get_user_from_token(token_key):
    try:
        access_token = AccessToken(token_key)
        user_id = access_token['user_id']
        user = User.objects.get(id=user_id)
        logger.info(f"WebSocket auth successful for user: {user.email}")
        return user
    except TokenError as e:
        logger.error(f"Token error: {e}")
        return AnonymousUser()
    except User.DoesNotExist:
        logger.error(f"User does not exist")
        return AnonymousUser()
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return AnonymousUser()


class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        token = None
        cookies = scope.get('cookies', {})
        
        logger.info(f"WebSocket connection - cookies: {list(cookies.keys())}")
        
        if cookies:
            token = cookies.get('access_token')
            if token:
                logger.info("Found access_token in cookies")
        
        if not token:
            query_string = scope.get('query_string', b'').decode()
            if query_string:
                for param in query_string.split('&'):
                    if param.startswith('token='):
                        token = param.split('=', 1)[1]
                        logger.info("Found token in query string")
                        break
        
        if not token:
            logger.warning("No token found in cookies or query string")
        
        if token:
            scope['user'] = await get_user_from_token(token)
        else:
            scope['user'] = AnonymousUser()
        
        return await super().__call__(scope, receive, send)
