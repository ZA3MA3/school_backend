import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from django.contrib.auth import get_user_model
from users.models import Message

logger = logging.getLogger(__name__)
User = get_user_model()


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        ticket = None
        query_string = self.scope.get('query_string', b'').decode()
        
        for param in query_string.split('&'):
            if param.startswith('ticket='):
                ticket = param.split('=', 1)[1]
                break
        
        if not ticket:
            logger.warning("WebSocket connection rejected - no ticket")
            await self.close()
            return
        """
        cache_key = f"ws_ticket:{ticket}"
        user_id = cache.get(cache_key)
        
        if not user_id:
            logger.warning("WebSocket connection rejected - invalid or expired ticket")
            await self.close()
            return
        
        cache.delete(cache_key)
        """
        cache_key = f"ws_ticket:{ticket}"
        claimed_key = f"ws_ticket_claimed:{ticket}"

        # Check if already claimed (prevents reuse without deleting)
        if cache.get(claimed_key):
            logger.warning("WebSocket connection rejected - ticket already in use")
            await self.close()
            return

        user_id = cache.get(cache_key)

        if not user_id:
            logger.warning("WebSocket connection rejected - invalid or expired ticket")
            await self.close()
            return

        # Mark as claimed atomically BEFORE accepting
        # TTL matches your ticket TTL (e.g. 60 seconds)
        cache.set(claimed_key, True, timeout=60)
        cache.delete(cache_key)
        try:
            self.user = await self.get_user(user_id)
        except User.DoesNotExist:
            logger.warning("WebSocket connection rejected - user not found")
            await self.close()
            return
        
        self.room_group_name = f"chat_{self.user.id}"
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info(f"WebSocket connected - user: {self.user.email}")
    
    @database_sync_to_async
    def get_user(self, user_id):
        return User.objects.get(id=user_id)
    
    async def disconnect(self, close_code):
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type', 'chat_message')
        
        if message_type == 'chat_message':
            receiver_id = data.get('receiver_id')
            content = data.get('content')
            
            if receiver_id and content:
                message = await self.save_message(receiver_id, content)
                
                message_data = {
                    'id': message.id,
                    'sender': self.user.id,
                    'sender_name': self.user.get_full_name,
                    'receiver': receiver_id,
                    'content': content,
                    'created_at': message.created_at.isoformat(),
                    'is_read': False
                }
                
                receiver_group = f"chat_{receiver_id}"
                await self.channel_layer.group_send(
                    receiver_group,
                    {
                        'type': 'chat_message',
                        'message': message_data
                    }
                )
                
                await self.send(text_data=json.dumps({
                    'type': 'new_message',
                    'message': message_data
        }))

    async def chat_unread_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_unread_update',
            'count': event.get('count', 0),
            'contact_id': event.get('contact_id')
        }))
    
    @database_sync_to_async
    def save_message(self, receiver_id, content):
        receiver = User.objects.get(id=receiver_id)
        
        message = Message.objects.create(
            sender=self.user,
            receiver=receiver,
            content=content
        )
        
        # Send chat unread count update to receiver
        from users.views import send_chat_unread_update
        send_chat_unread_update(receiver_id)
        
        return message
    
    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'message': event['message']
        }))


class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        ticket = None
        query_string = self.scope.get('query_string', b'').decode()
        
        for param in query_string.split('&'):
            if param.startswith('ticket='):
                ticket = param.split('=', 1)[1]
                break
        
        if not ticket:
            logger.warning("Notification WebSocket connection rejected - no ticket")
            await self.close()
            return
        
        cache_key = f"ws_ticket:{ticket}"
        user_id = cache.get(cache_key)
        
        if not user_id:
            logger.warning("Notification WebSocket connection rejected - invalid or expired ticket")
            await self.close()
            return
        
        cache.delete(cache_key)
        
        try:
            self.user = await self.get_user(user_id)
        except User.DoesNotExist:
            logger.warning("Notification WebSocket connection rejected - user not found")
            await self.close()
            return
        
        self.notification_group_name = f"notifications_{self.user.id}"
        
        await self.channel_layer.group_add(
            self.notification_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info(f"Notification WebSocket connected - user: {self.user.email}")
    
    @database_sync_to_async
    def get_user(self, user_id):
        return User.objects.get(id=user_id)
    
    async def disconnect(self, close_code):
        if hasattr(self, 'notification_group_name'):
            await self.channel_layer.group_discard(
                self.notification_group_name,
                self.channel_name
            )
    
    async def notification_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification_update',
            'count': event.get('count', 0)
        }))
    
    async def chat_unread_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_unread_update',
            'count': event.get('count', 0)
        }))
