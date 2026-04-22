from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import authenticate
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.conf import settings
from django.utils import timezone
from django.db import models
from django.core.cache import cache
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import secrets
from .serializers import LoginSerializer, ClassSerializer, ExerciseSerializer, ExerciseSubmissionSerializer, MessageSerializer, AnnouncementSerializer, AttendanceSerializer, NotificationSerializer, SkillSerializer
from .models import User, Class, Exercise, ExerciseSubmission, StudentProfile, TeacherProfile, ParentProfile, Message, Announcement, Attendance, Notification, Skill, ContactUs
from django_ratelimit.decorators import ratelimit


def has_role(user, role_name):
    """Helper to check if a user has a specific role."""
    return user.roles.filter(name=role_name).exists()


def send_notification_update(user_id):
    """
    Send WebSocket notification update to a user
    """
    try:
        channel_layer = get_channel_layer()
        count = Notification.objects.filter(recipient_id=user_id, is_read=False).count()
        async_to_sync(channel_layer.group_send)(
            f"notifications_{user_id}",
            {
                'type': 'notification_update',
                'count': count
            }
        )
    except Exception:
        pass


def send_chat_unread_update(user_id):
    """
    Send WebSocket chat unread count update to a user
    """
    try:
        channel_layer = get_channel_layer()
        count = Message.objects.filter(receiver_id=user_id, is_read=False).count()
        async_to_sync(channel_layer.group_send)(
            f"notifications_{user_id}",
            {
                'type': 'chat_unread_update',
                'count': count
            }
        )
    except Exception:
        pass



class LoginView(APIView):
    """
    Login endpoint that sets JWT token in HttpOnly cookie.
    """
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # Authenticate using email as the username field
        user = authenticate(request, username=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Create response with user data including all roles
            response = Response({
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'full_name': user.get_full_name,
                },
                'roles': list(user.roles.values_list('name', flat=True))
            })
            
            # Set HttpOnly cookies (for API auth)
            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=3600,
                path='/'
            )
            
            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=7 * 24 * 3600,
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
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'full_name': user.get_full_name,
            'roles': list(user.roles.values_list('name', flat=True))
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
            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=3600,
                path='/'
            )
            response.set_cookie(
                key='ws_token',
                value=access_token,
                httponly=False,
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


class TeacherClassesView(APIView):
    """
    Get all classes taught by the current teacher
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        classes = Class.objects.filter(teacher=teacher)
        serializer = ClassSerializer(classes, many=True)
        return Response(serializer.data)


class TeacherExercisesView(APIView):
    """
    Create exercise or list exercises for teacher's classes
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        exercises = Exercise.objects.filter(teacher=teacher)
        serializer = ExerciseSerializer(exercises, many=True, context={'request': request})
        return Response(serializer.data)
    
    def post(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can create exercises'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ExerciseSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            exercise = serializer.save(teacher=teacher)
            
            # Handle skills manually for FormData
            skills_ids = request.data.getlist('skills')
            if skills_ids:
                skill_ids = [int(sid) for sid in skills_ids if sid.isdigit()]
                if skill_ids:
                    exercise.skills.set(skill_ids)
            
            # Create notifications for students in the class
            if exercise.related_class:
                students = exercise.related_class.students.all()
                for student in students:
                    Notification.objects.create(
                        recipient=student.user,
                        type='EXERCISE',
                        message=f"New exercise uploaded: {exercise.title} in {exercise.related_class.name}"
                    )
                    send_notification_update(student.user.id)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AllClassesView(APIView):
    """
    Get all available classes (for students to browse and enroll)
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        classes = Class.objects.all()
        serializer = ClassSerializer(classes, many=True)
        return Response(serializer.data)


class StudentEnrollView(APIView):
    """
    Enroll a student in a class
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can enroll'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        class_id = request.data.get('class_id')
        if not class_id:
            return Response({'detail': 'class_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            class_obj = Class.objects.get(id=class_id)
        except Class.DoesNotExist:
            return Response({'detail': 'Class not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if already enrolled
        if student.enrolled_classes.filter(id=class_id).exists():
            return Response({'detail': 'Already enrolled in this class'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Enroll the student
        print(f"[DEBUG BACKEND] Enrolling student {student.id} in class {class_obj.id}")
        print(f"[DEBUG BACKEND] Before add: {class_obj.students.count()} students in class")
        student.enrolled_classes.add(class_obj)
        print(f"[DEBUG BACKEND] After add: {class_obj.students.count()} students in class")
        
        
        return Response({
            'detail': 'Successfully enrolled',
            'class_id': class_id,
            'class_name': class_obj.name
        }, status=status.HTTP_201_CREATED)


class StudentExercisesView(APIView):
    """
    Get exercises for classes a student is enrolled in
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get all exercises from classes the student is enrolled in
        exercises = Exercise.objects.filter(related_class__in=student.enrolled_classes.all())
        serializer = ExerciseSerializer(exercises, many=True, context={'request': request})
        return Response(serializer.data)


class StudentSubmissionView(APIView):
    """
    Submit an exercise or view submissions
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        submissions = ExerciseSubmission.objects.filter(student=student)
        serializer = ExerciseSubmissionSerializer(submissions, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can submit exercises'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ExerciseSubmissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(student=student)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TeacherSubmissionsView(APIView):
    """
    Get all submissions for exercises created by the teacher
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get all exercises created by this teacher
        teacher_exercises = Exercise.objects.filter(teacher=teacher)
        
        # Get all submissions for these exercises
        submissions = ExerciseSubmission.objects.filter(exercise__in=teacher_exercises)
        serializer = ExerciseSubmissionSerializer(submissions, many=True, context={'request': request})
        return Response(serializer.data)


class ParentChildrenView(APIView):
    """
    Get all children linked to the current parent
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'PARENT'):
            return Response({'detail': 'Only parents can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            parent = ParentProfile.objects.get(user=request.user)
        except ParentProfile.DoesNotExist:
            return Response({'detail': 'Parent profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        children = StudentProfile.objects.filter(parent_user=parent)
        from .serializers import StudentSerializer
        serializer = StudentSerializer(children, many=True)
        return Response(serializer.data)


class DownloadExerciseView(APIView):
    """
    Download an exercise file
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, exercise_id):
        exercise = get_object_or_404(Exercise, id=exercise_id)
        
        if exercise.file_path:
            file_path = exercise.file_path.path
            return FileResponse(
                open(file_path, 'rb'),
                as_attachment=True,
                filename=exercise.file_path.name.split('/')[-1]
            )
        
        return Response({'detail': 'No file attached to this exercise'}, status=status.HTTP_404_NOT_FOUND)


class DownloadSubmissionView(APIView):
    """
    Download a student's submission file
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, submission_id):
        submission = get_object_or_404(ExerciseSubmission, id=submission_id)
        
        # Check if user is the teacher who created the exercise or the student who submitted
        is_teacher = has_role(request.user, 'TEACHER')
        is_student = has_role(request.user, 'STUDENT')
        is_owner = submission.student.user_id == request.user.id if is_student else False
        is_exercise_teacher = submission.exercise.teacher.user_id == request.user.id if is_teacher else False
        
        if not (is_owner or is_exercise_teacher):
            return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        if submission.submission_file:
            file_path = submission.submission_file.path
            return FileResponse(
                open(file_path, 'rb'),
                as_attachment=True,
                filename=submission.submission_file.name.split('/')[-1]
            )
        
        return Response({'detail': 'No file submitted'}, status=status.HTTP_404_NOT_FOUND)


class GradeSubmissionView(APIView):
    """
    Grade a student's submission
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request, submission_id):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can grade submissions'}, status=status.HTTP_403_FORBIDDEN)
        
        submission = get_object_or_404(ExerciseSubmission, id=submission_id)
        
        # Verify the teacher owns this exercise
        if submission.exercise.teacher.user_id != request.user.id:
            return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        grade = request.data.get('grade')
        feedback = request.data.get('feedback', '')
        
        if grade is None:
            return Response({'detail': 'Grade is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            grade_value = float(grade)
            if grade_value < 0 or grade_value > 20:
                return Response({'detail': 'Grade must be between 0 and 20'}, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({'detail': 'Invalid grade value'}, status=status.HTTP_400_BAD_REQUEST)
        
        submission.grade = grade_value
        submission.feedback = feedback
        submission.graded_at = timezone.now()
        submission.save()
        
        # Create notification for student
        Notification.objects.create(
            recipient=submission.student.user,
            type='GRADE',
            message=f"Your submission for {submission.exercise.title} has been graded: {grade_value}/20"
        )
        send_notification_update(submission.student.user.id)
        
        # Create notification for parent if exists
        try:
            student = StudentProfile.objects.get(id=submission.student.id)
            if student.parent_user:
                Notification.objects.create(
                    recipient=student.parent_user.user,
                    type='GRADE',
                    message=f"{student.get_full_name}'s submission for {submission.exercise.title} has been graded: {grade_value}/20"
                )
                send_notification_update(student.parent_user.user.id)
        except StudentProfile.DoesNotExist:
            pass
        
        serializer = ExerciseSubmissionSerializer(submission)
        return Response(serializer.data)


class ChatContactsView(APIView):
    """
    Get contacts for chat (Parents for teachers, Teachers for parents)
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        from django.db import connection
        user_id = request.user.id
        role = request.query_params.get('role')
        
        is_teacher = has_role(request.user, 'TEACHER')
        is_parent = has_role(request.user, 'PARENT')
        
        if role == 'TEACHER' or (not role and is_teacher):
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT p.user_id
                    FROM parents p
                    JOIN students s ON s.parent_user_id = p.id
                    JOIN classes_students cs ON cs.studentprofile_id = s.id
                    JOIN classes c ON c.id = cs.class_id
                    JOIN teachers t ON t.id = c.teacher_id
                    WHERE t.user_id = %s AND p.user_id != %s
                """, [user_id, user_id])
                contact_user_ids = [row[0] for row in cursor.fetchall()]
            
            contacts = User.objects.filter(id__in=contact_user_ids)
            data = [{
                'id': u.id,
                'full_name': u.get_full_name,
                'role': 'PARENT'
            } for u in contacts]
            
        elif role == 'PARENT' or (not role and is_parent):
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT t.user_id
                    FROM teachers t
                    JOIN classes c ON c.teacher_id = t.id
                    JOIN classes_students cs ON cs.class_id = c.id
                    JOIN students s ON s.id = cs.studentprofile_id
                    WHERE s.parent_user_id = (
                        SELECT id FROM parents WHERE user_id = %s
                    ) AND t.user_id != %s
                """, [user_id, user_id])
                contact_user_ids = [row[0] for row in cursor.fetchall()]
            
            contacts = User.objects.filter(id__in=contact_user_ids)
            data = [{
                'id': u.id,
                'full_name': u.get_full_name,
                'role': 'TEACHER'
            } for u in contacts]
            
        else:
            return Response({'detail': 'Only teachers and parents can access contacts'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response(data)


class ChatMessagesView(APIView):
    """
    Get messages between current user and a specific contact
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, contact_id):
        user = request.user
        
        # Get messages where user is sender or receiver with this contact
        messages = Message.objects.filter(
            (models.Q(sender=user) & models.Q(receiver_id=contact_id)) |
            (models.Q(sender_id=contact_id) & models.Q(receiver=user))
        ).order_by('created_at')
        
        # Mark messages as read
        messages.filter(receiver=user, is_read=False).update(is_read=True)
        
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)
    
    def post(self, request, contact_id):
        user = request.user
        
        # Validate that contact exists
        try:
            User.objects.get(id=contact_id)
        except User.DoesNotExist:
            return Response({'detail': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        
        content = request.data.get('content')
        if not content:
            return Response({'detail': 'Content is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        message = Message.objects.create(
            sender=user,
            receiver_id=contact_id,
            content=content
        )
        
        # Send chat unread count update to receiver
        send_chat_unread_update(contact_id)
        
        serializer = MessageSerializer(message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class WSTicketView(APIView):
    """
    Generate a one-time WebSocket ticket for authenticated users.
    """
    def post(self, request):
        ticket = secrets.token_urlsafe(32)
        cache_key = f"ws_ticket:{ticket}"
        cache.set(cache_key, request.user.id, timeout=30)
        return Response({'ticket': ticket})


class ChatUnreadCountView(APIView):
    """
    Get unread message counts for the current user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        role = request.query_params.get('role')
        
        is_teacher = has_role(user, 'TEACHER')
        is_parent = has_role(user, 'PARENT')
        
        contact_user_ids = []
        
        if role == 'TEACHER' or (not role and is_teacher):
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT p.user_id
                    FROM parents p
                    JOIN students s ON s.parent_user_id = p.id
                    JOIN classes_students cs ON cs.studentprofile_id = s.id
                    JOIN classes c ON c.id = cs.class_id
                    JOIN teachers t ON t.id = c.teacher_id
                    WHERE t.user_id = %s AND p.user_id != %s
                """, [user.id, user.id])
                contact_user_ids = [row[0] for row in cursor.fetchall()]
                
        elif role == 'PARENT' or (not role and is_parent):
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT t.user_id
                    FROM teachers t
                    JOIN classes c ON c.teacher_id = t.id
                    JOIN classes_students cs ON cs.class_id = c.id
                    JOIN students s ON s.id = cs.studentprofile_id
                    WHERE s.parent_user_id = (
                        SELECT id FROM parents WHERE user_id = %s
                    ) AND t.user_id != %s
                """, [user.id, user.id])
                contact_user_ids = [row[0] for row in cursor.fetchall()]
        else:
            return Response({'detail': 'Only teachers and parents can access contacts'}, status=status.HTTP_403_FORBIDDEN)
        
        # Get unread counts per contact
        contact_counts = {}
        for contact_user_id in contact_user_ids:
            count = Message.objects.filter(
                sender_id=contact_user_id,
                receiver=user,
                is_read=False
            ).count()
            if count > 0:
                contact_counts[contact_user_id] = count
        
        # Get total unread count
        total_unread = Message.objects.filter(receiver=user, is_read=False).count()
        
        return Response({
            'contact_counts': contact_counts,
            'total_unread': total_unread
        })


class TeacherAnnouncementView(APIView):
    """
    Get all announcements created by the current teacher, or create a new one
    """
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher not found'}, status=status.HTTP_404_NOT_FOUND)
        
        announcements = Announcement.objects.filter(teacher=teacher)
        serializer = AnnouncementSerializer(announcements, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can create announcements'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AnnouncementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        announcement = serializer.save(teacher=teacher)
        
        # Create notifications for students
        notified_students = set()
        notified_parents = set()
        
        if announcement.related_class:
            students = announcement.related_class.students.all().distinct()
            for student in students:
                if student.user_id not in notified_students:
                    Notification.objects.create(
                        recipient=student.user,
                        type='ANNOUNCEMENT',
                        message=f"New announcement: {announcement.title}"
                    )
                    send_notification_update(student.user_id)
                    notified_students.add(student.user_id)
                    
                    if student.parent_user and student.parent_user.user_id not in notified_parents:
                        Notification.objects.create(
                            recipient=student.parent_user.user,
                            type='ANNOUNCEMENT',
                            message=f"New announcement for {student.get_full_name}: {announcement.title}"
                        )
                        send_notification_update(student.parent_user.user_id)
                        notified_parents.add(student.parent_user.user_id)
        else:
            # Notify all students in teacher's classes
            classes = Class.objects.filter(teacher=teacher)
            for cls in classes:
                for student in cls.students.all():
                    if student.user_id not in notified_students:
                        Notification.objects.create(
                            recipient=student.user,
                            type='ANNOUNCEMENT',
                            message=f"New announcement: {announcement.title}"
                        )
                        send_notification_update(student.user_id)
                        notified_students.add(student.user_id)
                        
                        if student.parent_user and student.parent_user.user_id not in notified_parents:
                            Notification.objects.create(
                                recipient=student.parent_user.user,
                                type='ANNOUNCEMENT',
                                message=f"New announcement for {student.get_full_name}: {announcement.title}"
                            )
                            send_notification_update(student.parent_user.user_id)
                            notified_parents.add(student.parent_user.user_id)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class StudentAnnouncementView(APIView):
    """
    Get all announcements for the current student's enrolled classes
    """
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)
        
        enrolled_classes = student.enrolled_classes.all()
        announcements = Announcement.objects.filter(
            models.Q(related_class__in=enrolled_classes) | models.Q(related_class__isnull=True, teacher__classes_taught__in=enrolled_classes)
        ).distinct()
        
        serializer = AnnouncementSerializer(announcements, many=True)
        return Response(serializer.data)


class ParentAnnouncementView(APIView):
    """
    Get all announcements for children of the current parent
    """
    def get(self, request):
        if not has_role(request.user, 'PARENT'):
            return Response({'detail': 'Only parents can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            parent = ParentProfile.objects.get(user=request.user)
        except ParentProfile.DoesNotExist:
            return Response({'detail': 'Parent not found'}, status=status.HTTP_404_NOT_FOUND)
        
        children = parent.children.all()
        
        announcements = []
        for child in children:
            child_classes = child.enrolled_classes.all()
            child_announcements = Announcement.objects.filter(
                models.Q(related_class__in=child_classes) | models.Q(related_class__isnull=True, teacher__classes_taught__in=child_classes)
            ).distinct()
            
            for ann in child_announcements:
                announcements.append({
                    'child_name': child.get_full_name,
                    'announcement': AnnouncementSerializer(ann).data
                })
        
        return Response(announcements)


class TeacherAttendanceView(APIView):
    """
    Post attendance for students in a class, or get attendance for a class on a date
    """
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        class_id = request.query_params.get('class_id')
        date = request.query_params.get('date')
        
        if not class_id or not date:
            return Response({'detail': 'class_id and date are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
            related_class = Class.objects.get(id=class_id, teacher=teacher)
        except (TeacherProfile.DoesNotExist, Class.DoesNotExist):
            return Response({'detail': 'Class not found'}, status=status.HTTP_404_NOT_FOUND)
        
        attendance = Attendance.objects.filter(related_class=related_class, date=date)
        serializer = AttendanceSerializer(attendance, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can mark attendance'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher not found'}, status=status.HTTP_404_NOT_FOUND)
        
        records = request.data.get('records', [])
        if not records:
            return Response({'detail': 'No attendance records provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        created_records = []
        errors = []
        for record in records:
            student_id = record.get('student_id')
            class_id = record.get('class_id')
            date = record.get('date')
            status_val = record.get('status')
            
            if not all([student_id, class_id, date, status_val]):
                errors.append(f'Missing required fields for record: {record}')
                continue
            
            try:
                related_class = Class.objects.get(id=class_id)
                student = StudentProfile.objects.get(id=student_id)
            except (Class.DoesNotExist, StudentProfile.DoesNotExist) as e:
                errors.append(f'Record not found: {e}')
                continue
            
            attendance, created = Attendance.objects.update_or_create(
                student=student,
                related_class=related_class,
                date=date,
                defaults={
                    'status': status_val,
                    'marked_by': teacher
                }
            )
            created_records.append(attendance)
            
            # Create notification for absence
            if status_val == 'ABSENT':
                Notification.objects.create(
                    recipient=student.user,
                    type='ABSENCE',
                    message=f"You were marked absent in {related_class.name} on {date}"
                )
                send_notification_update(student.user.id)
                # Also notify parent
                if student.parent_user:
                    Notification.objects.create(
                        recipient=student.parent_user.user,
                        type='ABSENCE',
                        message=f"{student.get_full_name} was marked absent in {related_class.name} on {date}"
                    )
                    send_notification_update(student.parent_user.user.id)
        
        if errors:
            return Response({'detail': 'Some records failed', 'errors': errors}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = AttendanceSerializer(created_records, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class StudentAttendanceView(APIView):
    """
    Get attendance for the current student
    """
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            student = StudentProfile.objects.get(user=request.user)
        except StudentProfile.DoesNotExist:
            return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)
        
        attendance = Attendance.objects.filter(student=student)
        serializer = AttendanceSerializer(attendance, many=True)
        return Response(serializer.data)


class ParentAttendanceView(APIView):
    """
    Get attendance for children of the current parent
    """
    def get(self, request):
        if not has_role(request.user, 'PARENT'):
            return Response({'detail': 'Only parents can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            parent = ParentProfile.objects.get(user=request.user)
        except ParentProfile.DoesNotExist:
            return Response({'detail': 'Parent not found'}, status=status.HTTP_404_NOT_FOUND)
        
        children = parent.children.all()
        
        result = []
        for child in children:
            attendance = Attendance.objects.filter(student=child)
            serializer = AttendanceSerializer(attendance, many=True)
            result.append({
                'child_name': child.get_full_name,
                'attendance': serializer.data
            })
        
        return Response(result)


class NotificationListView(APIView):
    """
    Get all notifications for the current user
    """
    def get(self, request):
        notifications = Notification.objects.filter(recipient=request.user)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)


class NotificationUnreadCountView(APIView):
    """
    Get count of unread notifications
    """
    def get(self, request):
        count = Notification.objects.filter(recipient=request.user, is_read=False).count()
        return Response({'count': count})


class NotificationMarkReadView(APIView):
    """
    Mark a notification as read
    """
    def post(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id, recipient=request.user)
            notification.is_read = True
            notification.save()
            send_notification_update(request.user.id)
            return Response({'detail': 'Notification marked as read'})
        except Notification.DoesNotExist:
            return Response({'detail': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)


class SkillListView(APIView):
    """
    List all skills for exercises
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        skills = Skill.objects.all()
        serializer = SkillSerializer(skills, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        if not has_role(request.user, 'TEACHER') and not has_role(request.user, 'ADMIN'):
            return Response({'detail': 'Only teachers or admins can create skills'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = SkillSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StudentPredictionView(APIView):
    """
    Predict student dropout/graduation based on their data
    GET /api/predict/student/<student_id>/
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, student_id):
        # Check if user has permission to view this student's prediction
        # Parents can view their children's predictions
        # Teachers can view their students' predictions
        # Admins can view any
        
        user = request.user
        
        # Check parent relationship
        if has_role(user, 'PARENT'):
            try:
                parent = ParentProfile.objects.get(user=user)
                # Check if this student is linked to the parent
                student_ids = list(parent.children.values_list('id', flat=True))
                if student_id not in student_ids:
                    return Response({'detail': 'You are not authorized to view this student\'s prediction'}, status=status.HTTP_403_FORBIDDEN)
            except ParentProfile.DoesNotExist:
                return Response({'detail': 'Parent profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Check teacher relationship
        if has_role(user, 'TEACHER'):
            try:
                student = StudentProfile.objects.get(pk=student_id)
                # Check if student is in any of teacher's classes
                teacher = TeacherProfile.objects.get(user=user)
                classes = Class.objects.filter(teacher=teacher)
                students_in_classes = set()
                for cls in classes:
                    for s in cls.students.all():
                        students_in_classes.add(s.id)
                if student_id not in students_in_classes:
                    return Response({'detail': 'You are not authorized to view this student\'s prediction'}, status=status.HTTP_403_FORBIDDEN)
            except StudentProfile.DoesNotExist:
                return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Make prediction
        try:
            from .apps import predict_student_dropout
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Making prediction for student {student_id}")
            result = predict_student_dropout(student_id)
            logger.info(f"Prediction result: {result}")
            return Response(result)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Prediction error: {str(e)}", exc_info=True)
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([])  # No auth required
@ratelimit(key='ip', rate='3/h', method='POST', block=False)
def contact_view(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return Response(
            {"detail": "You have submitted too many requests. Please try again later."},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    name = request.data.get('name')
    email = request.data.get('email')
    message = request.data.get('message')

    if not name or not email or not message:
        return Response(
            {"detail": "Name, email, and message are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    ContactUs.objects.create(name=name, email=email, message=message)
    
    return Response(
        {"detail": "Your message has been sent successfully."},
        status=status.HTTP_201_CREATED
    )

