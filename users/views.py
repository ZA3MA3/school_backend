from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
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
import requests
import hashlib
import hmac
import json
from .serializers import LoginSerializer, ClassSerializer, ExerciseSerializer, ExerciseSubmissionSerializer, MessageSerializer, AnnouncementSerializer, AttendanceSerializer, NotificationSerializer, SkillSerializer, EnrollmentSerializer
from .models import User, Class, ClassTeacher, Exercise, ExerciseSubmission, StudentProfile, TeacherProfile, ParentProfile, Message, Announcement, Attendance, Notification, Skill, ContactUs, Enrollment, EnrollmentStatus, PhoneOTP, Role, Payment
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
        
        classes = Class.objects.filter(teachers=teacher)
        serializer = ClassSerializer(classes, many=True)
        return Response(serializer.data)


class TeacherEnrollmentsView(APIView):
    """
    Get pending enrollment requests for teacher's classes, or approve/reject
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
# Get classes taught by this teacher
        class_ids = Class.objects.filter(teachers=teacher).values_list('id', flat=True)
        
        # Get pending enrollment requests for those classes
        enrollments = Enrollment.objects.filter(
            class_teacher__class_obj_id__in=class_ids,
            status=EnrollmentStatus.PENDING
        ).select_related('student__user', 'class_teacher__class_obj')
        
        serializer = EnrollmentSerializer(enrollments, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Approve or reject an enrollment request"""
        if not has_role(request.user, 'TEACHER'):
            return Response({'detail': 'Only teachers can respond to enrollments'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            teacher = TeacherProfile.objects.get(user=request.user)
        except TeacherProfile.DoesNotExist:
            return Response({'detail': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        enrollment_id = request.data.get('enrollment_id')
        action = request.data.get('action')  # 'approve' or 'reject'
        
        if not enrollment_id or not action:
            return Response({'detail': 'enrollment_id and action are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if action not in ['approve', 'reject']:
            return Response({'detail': 'action must be approve or reject'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find the enrollment
        try:
            enrollment = Enrollment.objects.get(id=enrollment_id)
        except Enrollment.DoesNotExist:
            return Response({'detail': 'Enrollment not found'}, status=status.HTTP_404_NOT_FOUND)
        
# Verify teacher teaches this class
        if teacher not in enrollment.class_teacher.class_obj.teachers.all():
            return Response({'detail': 'You are not authorized to respond to this enrollment'}, status=status.HTTP_403_FORBIDDEN)
        
        if action == 'approve':
            enrollment.status = EnrollmentStatus.APPROVED
            enrollment.responded_at = timezone.now()
            enrollment.save()
            Notification.objects.create(
                recipient=enrollment.student.user,
                type='ENROLLMENT',
                message=f"Your request to join {enrollment.class_teacher.class_obj.name} has been approved"
            )
            send_notification_update(enrollment.student.user.id)
            return Response({'detail': 'Enrollment approved', 'status': 'APPROVED'})
        else:
            enrollment.status = EnrollmentStatus.REJECTED
            enrollment.responded_at = timezone.now()
            enrollment.save()
            Notification.objects.create(
                recipient=enrollment.student.user,
                type='ENROLLMENT',
                message=f"Your request to join {enrollment.class_teacher.class_obj.name} has been rejected"
            )
            send_notification_update(enrollment.student.user.id)
            return Response({'detail': 'Enrollment rejected', 'status': 'REJECTED'})


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
        
        student_id = request.query_params.get('student_id')
        
        context = {'request': request}
        if student_id:
            context['student_id'] = int(student_id)
        
        classes = Class.objects.all()
        serializer = ClassSerializer(classes, many=True, context=context)
        return Response(serializer.data)


class StudentEnrollView(APIView):
    """
    Request enrollment in a class (creates PENDING request)
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can request enrollment'}, status=status.HTTP_403_FORBIDDEN)
        
        student_id = request.data.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                student = StudentProfile.objects.get(user=request.user)
            except StudentProfile.DoesNotExist:
                return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        class_teacher_id = request.data.get('class_teacher_id')
        if not class_teacher_id:
            return Response({'detail': 'class_teacher_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            class_teacher = ClassTeacher.objects.select_related('class_obj').get(id=class_teacher_id)
        except ClassTeacher.DoesNotExist:
            return Response({'detail': 'Class-Teacher assignment not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if there's an existing enrollment request
        existing_enrollment = Enrollment.objects.filter(student=student, class_teacher=class_teacher).first()
        if existing_enrollment:
            if existing_enrollment.status == EnrollmentStatus.APPROVED:
                return Response({'detail': 'Already enrolled in this class'}, status=status.HTTP_400_BAD_REQUEST)
            elif existing_enrollment.status == EnrollmentStatus.PENDING:
                return Response({'detail': 'Enrollment request already pending'}, status=status.HTTP_400_BAD_REQUEST)
            elif existing_enrollment.status == EnrollmentStatus.REJECTED:
                # Resubmit - create new pending request
                existing_enrollment.status = EnrollmentStatus.PENDING
                existing_enrollment.requested_at = timezone.now()
                existing_enrollment.responded_at = None
                existing_enrollment.save()
                return Response({'detail': 'Enrollment request resubmitted', 'status': 'PENDING'})
        
        # Create new enrollment request
        enrollment = Enrollment.objects.create(
            student=student,
            class_teacher=class_teacher,
            status=EnrollmentStatus.PENDING
        )
        
        # Notify the teacher
        Notification.objects.create(
            recipient=class_teacher.teacher.user,
            type='ENROLLMENT',
            message=f"{student.get_full_name} requested to join {class_teacher.class_obj.name}"
        )
        send_notification_update(class_teacher.teacher.user.id)
        
        return Response({
            'detail': 'Enrollment request submitted',
            'status': 'PENDING',
            'requested_at': enrollment.requested_at.isoformat()
        }, status=status.HTTP_201_CREATED)


class StudentExercisesView(APIView):
    """
    Get exercises for classes a student is enrolled in
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not has_role(request.user, 'STUDENT'):
            return Response({'detail': 'Only students can access this endpoint'}, status=status.HTTP_403_FORBIDDEN)
        
        # Get all exercises from classes the student is enrolled in
        student_id = request.query_params.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                student = StudentProfile.objects.get(user=request.user)
            except StudentProfile.DoesNotExist:
                return Response({'detail': 'Student profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        enrolled_class_ids = Enrollment.objects.filter(
            student=student,
            status=EnrollmentStatus.APPROVED
        ).values_list('class_teacher__class_obj_id', flat=True)
        exercises = Exercise.objects.filter(related_class__in=enrolled_class_ids)
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
        
        student_id = request.query_params.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
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
        
        student_id = request.data.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
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
                    JOIN enrollment e ON e.student_id = s.id AND e.status = 'APPROVED'
                    JOIN classes_teachers ct ON ct.id = e.class_teacher_id
                    JOIN classes c ON c.id = ct.class_id
                    JOIN teachers t ON t.id = ct.teacher_id
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
                    JOIN classes_teachers ct ON ct.teacher_id = t.id
                    JOIN classes c ON c.id = ct.class_id
                    JOIN enrollment e ON e.class_teacher_id = ct.id AND e.status = 'APPROVED'
                    JOIN students s ON s.id = e.student_id
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
                    JOIN enrollment e ON e.student_id = s.id AND e.status = 'APPROVED'
                    JOIN classes_teachers ct ON ct.id = e.class_teacher_id
                    JOIN classes c ON c.id = ct.class_id
                    JOIN teachers t ON t.id = ct.teacher_id
                    WHERE t.user_id = %s AND p.user_id != %s
                """, [user.id, user.id])
                contact_user_ids = [row[0] for row in cursor.fetchall()]
        elif role == 'PARENT' or (not role and is_parent):
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT t.user_id
                    FROM teachers t
                    JOIN classes_teachers ct ON ct.teacher_id = t.id
                    JOIN classes c ON c.id = ct.class_id
                    JOIN enrollment e ON e.class_teacher_id = ct.id AND e.status = 'APPROVED'
                    JOIN students s ON s.id = e.student_id
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
            classes = Class.objects.filter(teachers=teacher)
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
        
        student_id = request.query_params.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                student = StudentProfile.objects.get(user=request.user)
            except StudentProfile.DoesNotExist:
                return Response({'detail': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)
        
        enrolled_class_ids = Enrollment.objects.filter(
                student=student, 
                status=EnrollmentStatus.APPROVED
        ).values_list('class_teacher__class_obj_id', flat=True)
        
        announcements = Announcement.objects.filter(
            #models.Q(related_class__in=enrolled_class_ids) | models.Q(related_class__isnull=True, teacher__classes_taught__class_obj__in=enrolled_class_ids)
            models.Q(related_class_id__in=enrolled_class_ids) |
            models.Q(related_class__isnull=True)
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
            child_class_ids = Enrollment.objects.filter(
                student=child, 
                status=EnrollmentStatus.APPROVED
            ).values_list('class_teacher__class_obj_id', flat=True)
            child_announcements = Announcement.objects.filter(
                models.Q(related_class__in=child_class_ids) | models.Q(related_class__isnull=True, teacher__classes_taught__class_obj__in=child_class_ids)
            ).distinct()
            
            for ann in child_announcements:
                announcements.append({
                    'child_name': child.get_full_name(),
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
        
        student_id = request.query_params.get('student_id')
        
        if student_id:
            try:
                student = StudentProfile.objects.get(id=int(student_id), parent_user__user=request.user)
            except (StudentProfile.DoesNotExist, ValueError):
                return Response({'detail': 'Child student not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
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
        
        # Check if user is authorized via any role
        can_view = False
        
        # Check parent relationship
        if has_role(user, 'PARENT'):
            try:
                parent = ParentProfile.objects.get(user=user)
                student_ids = list(parent.children.values_list('id', flat=True))
                if student_id in student_ids:
                    can_view = True
            except ParentProfile.DoesNotExist:
                pass
        
        # Check teacher relationship
        if not can_view and has_role(user, 'TEACHER'):
            try:
                teacher = TeacherProfile.objects.get(user=user)
                if Class.objects.filter(teacher=teacher, students__id=student_id).exists():
                    can_view = True
            except TeacherProfile.DoesNotExist:
                pass
        
        # Check if admin
        if not can_view and has_role(user, 'ADMIN'):
            can_view = True
        
        if not can_view:
            return Response({'detail': 'You are not authorized to view this student\'s prediction'}, status=status.HTTP_403_FORBIDDEN)
        
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


class SendOTPView(APIView):
    """Send OTP to phone number"""
    permission_classes = []  # No auth required
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        
        if not phone_number:
            return Response({'detail': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if using test credentials
        is_test_mode = getattr(settings, 'TWILIO_USE_TEST', False)
        
        # Generate 6-digit code
        import random
        code = '123456' if is_test_mode else str(random.randint(100000, 999999))
        
        # Set expiry to 10 minutes from now
        from django.utils import timezone
        from datetime import timedelta
        expires_at = timezone.now() + timedelta(minutes=10)
        
        # Create OTP record
        otp = PhoneOTP.objects.create(
            phone_number=phone_number,
            code=code,
            expires_at=expires_at
        )
        
        # Send SMS via Twilio
        try:
            from twilio.rest import Client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                body=f'Your verification code is: {code}',
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            return Response({'detail': 'OTP sent successfully', 'sid': message.sid})
        except Exception as e:
            otp.delete()
            return Response({'detail': f'Failed to send SMS: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    """Verify OTP and update user phone"""
    permission_classes = []
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        code = request.data.get('code')
        email = request.data.get('email')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        address = request.data.get('address', '')
        date_of_birth = request.data.get('date_of_birth', '')
        
        if not phone_number or not code:
            return Response({'detail': 'Phone number and code are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not email:
            return Response({'detail': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find valid OTP
        try:
            otp = PhoneOTP.objects.get(
                phone_number=phone_number,
                code=code,
                is_used=False,
                expires_at__gte=timezone.now()
            )
        except PhoneOTP.DoesNotExist:
            return Response({'detail': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Mark OTP as used
        otp.is_used = True
        otp.save()
        
        # Find user by email and update all fields
        try:
            user = User.objects.get(email=email)
            user.phone_number = phone_number
            user.phone_verified = True
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            if address:
                user.address = address
            if date_of_birth:
                user.date_of_birth = date_of_birth
            user.save()
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({'detail': 'Phone verified successfully'})


class GoogleAuthView(APIView):
    """Handle Google OAuth login/signup from frontend"""
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        print(f"[DEBUG] GoogleAuthView called")
        print(f"[DEBUG] Request data: {request.data}")
        
        access_token = request.data.get('access_token')
        
        if not access_token:
            print(f"[DEBUG] No access token in request")
            return Response({'detail': 'Access token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        print(f"[DEBUG] Got access_token: {access_token[:20]}...")
        
        # Verify the token with Google's tokeninfo endpoint
        try:
            import requests
            token_info_url = 'https://oauth2.googleapis.com/tokeninfo'
            params = {'access_token': access_token}
            print(f"[DEBUG] Calling Google tokeninfo endpoint...")
            resp = requests.get(token_info_url, params=params)
            print(f"[DEBUG] Google response status: {resp.status_code}")
            print(f"[DEBUG] Google response text: {resp.text}")
            
            if resp.status_code != 200:
                return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            
            idinfo = resp.json()
            print(f"[DEBUG] tokeninfo response: {idinfo}")
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            print(f"[DEBUG] email={email}, first_name={first_name}, last_name={last_name}")
            
        except Exception as e:
            print(f"[DEBUG] Exception: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({'detail': f'Token verification failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find or create user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'password': make_password(None),
            }
        )
        print(f"[DEBUG] user found/created: {user.email}, created={created}")
        
        # Check if this is a new user - set default role if needed
        if created:
            # Try to assign a default role (optional - you might want to adjust this)
            pass
        
        # Generate JWT tokens for the user
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        
        # Set response with JWT in cookie
        response = Response({
            'detail': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
        
        # Set the JWT cookie
        from django.conf import settings
        response.set_cookie(
            'access_token',
            str(refresh.access_token),
            httponly=True,
            samesite='Lax',
            max_age=3600,
        )
        response.set_cookie(
            'refresh_token',
            str(refresh),
            httponly=True,
            samesite='Lax',
            max_age=7*24*3600,
        )
        
        return response


class TeacherProfileCreateView(APIView):
    """Create teacher profile with class after phone verification"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        hire_date = request.data.get('hire_date')
        specialization = request.data.get('specialization')
        class_name = request.data.get('class_name')
        class_description = request.data.get('class_description')
        
        if not hire_date or not specialization or not class_name:
            return Response({'detail': 'hire_date, specialization, and class_name are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        
        # Create teacher profile
        teacher = TeacherProfile.objects.create(
            user=user,
            hire_date=hire_date,
            specialization=specialization
        )
        
# Create class
        class_obj = Class.objects.create(
            name=class_name,
            description=class_description or ''
        )
        class_obj.teachers.add(teacher)
        
        # Add TEACHER role
        teacher_role = Role.objects.get(name='TEACHER')
        user.roles.add(teacher_role)
        
        return Response({'detail': 'Teacher profile created successfully'})


class ParentStudentCreateView(APIView):
    """Create parent profile with students after phone verification"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        occupation = request.data.get('occupation')
        students = request.data.get('students', [])
        
        if not occupation:
            return Response({'detail': 'occupation is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not students or len(students) == 0:
            return Response({'detail': 'At least one student is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        
        # Create parent profile
        parent = ParentProfile.objects.create(
            user=user,
            occupation=occupation
        )
        
        # Create students
        for student_data in students:
            first_name = student_data.get('first_name')
            last_name = student_data.get('last_name')
            enrollment_date = student_data.get('enrollment_date')
            date_of_birth = student_data.get('date_of_birth')
            gender = student_data.get('gender', True)
            
            if not first_name or not last_name or not enrollment_date:
                continue
            
            StudentProfile.objects.create(
                first_name=first_name,
                last_name=last_name,
                enrollment_date=enrollment_date,
                date_of_birth=date_of_birth or None,
                gender=gender,
                scholarship_holder=False,
                parent_user=parent
            )
        
        # Add PARENT and STUDENT roles
        parent_role = Role.objects.get(name='PARENT')
        student_role = Role.objects.get(name='STUDENT')
        user.roles.add(parent_role)
        user.roles.add(student_role)
        
        return Response({'detail': 'Parent profile and students created successfully'})


# ===============================================
# PHONE LOGIN VIEWS (Login flow only - not signup)
# ===============================================

class PhoneLoginSendView(APIView):
    """Send OTP for phone login - Step 1"""
    permission_classes = []
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        
        if not phone_number:
            return Response({'detail': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user exists and is verified
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({'detail': 'User not found with this phone number'}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.phone_verified:
            return Response({'detail': 'Phone number not verified. Please verify your phone first.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate 6-digit code
        import random
        is_test_mode = 'test' in settings.TWILIO_ACCOUNT_SID.lower() if settings.TWILIO_ACCOUNT_SID else False
        code = '123456' if is_test_mode else str(random.randint(100000, 999999))
        
        # Set expiry to 10 minutes from now
        from django.utils import timezone
        from datetime import timedelta
        expires_at = timezone.now() + timedelta(minutes=10)
        
        # Create OTP record
        otp = PhoneOTP.objects.create(
            phone_number=phone_number,
            code=code,
            expires_at=expires_at
        )
        
        # Send SMS via Twilio
        try:
            from twilio.rest import Client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                body=f'Your login verification code is: {code}',
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            return Response({'detail': 'OTP sent successfully', 'sid': message.sid})
        except Exception as e:
            otp.delete()
            return Response({'detail': f'Failed to send SMS: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PhoneLoginVerifyView(APIView):
    """Verify OTP and login - Step 2"""
    permission_classes = []
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        code = request.data.get('code')
        
        if not phone_number or not code:
            return Response({'detail': 'Phone number and code are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find valid OTP
        try:
            otp = PhoneOTP.objects.get(
                phone_number=phone_number,
                code=code,
                is_used=False,
                expires_at__gte=timezone.now()
            )
        except PhoneOTP.DoesNotExist:
            return Response({'detail': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Mark OTP as used
        otp.is_used = True
        otp.save()
        
        # Find user by phone and verify
        try:
            user = User.objects.get(phone_number=phone_number, phone_verified=True)
        except User.DoesNotExist:
            return Response({'detail': 'User not found or not verified'}, status=status.HTTP_404_NOT_FOUND)
        
        # Generate JWT tokens
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        
        # Create response
        response = Response({
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'roles': list(user.roles.values_list('name', flat=True)),
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
        
        # Set HttpOnly cookies
        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            samesite='Lax',
            max_age=3600,
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            samesite='Lax',
            max_age=7*24*3600,
        )
        
        return response


class GoogleLoginOnlyView(APIView):
    """Google login for existing users only - NOT for signup"""
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        access_token = request.data.get('access_token')
        
        if not access_token:
            return Response({'detail': 'Access token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the token with Google's tokeninfo endpoint
        try:
            import requests
            token_info_url = 'https://oauth2.googleapis.com/tokeninfo'
            params = {'access_token': access_token}
            resp = requests.get(token_info_url, params=params)
            
            if resp.status_code != 200:
                return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            
            idinfo = resp.json()
            email = idinfo.get('email')
            
        except Exception as e:
            return Response({'detail': f'Token verification failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user by email - do NOT create if not found
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'No account found with this Google email. Please sign up first.'}, status=status.HTTP_404_NOT_FOUND)
        
        # Generate JWT tokens
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        
        # Create response
        response = Response({
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'roles': list(user.roles.values_list('name', flat=True)),
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
        
        # Set HttpOnly cookies
        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            samesite='Lax',
            max_age=3600,
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            samesite='Lax',
            max_age=7*24*3600,
        )
        
        return response


class CreateCheckoutView(APIView):
    permission_classes = [IsAuthenticated]

    PLAN_PRICES = {
        'TEACHER_PARENT': 5000,
        'TEACHER_ONLY': 3000,
        'PARENT_ONLY': 2000,
    }

    PLAN_NAMES = {
        'TEACHER_PARENT': 'Teacher + Parent Plan',
        'TEACHER_ONLY': 'Teacher Plan',
        'PARENT_ONLY': 'Parent Plan',
    }

    def post(self, request):
        plan_type = request.data.get('plan_type', 'TEACHER_PARENT')
        
        if plan_type not in self.PLAN_PRICES:
            return Response({'error': 'Invalid plan type'}, status=400)
        
        amount = self.PLAN_PRICES[plan_type]
        description = self.PLAN_NAMES[plan_type]

        response = requests.post(
            f'{settings.CHARGILY_BASE_URL}/checkouts',
            headers={
                'Authorization': f'Bearer {settings.CHARGILY_API_KEY}',
                'Content-Type': 'application/json',
            },
            json={
                'amount': int(amount),
                'currency': 'dzd',
                'success_url': f'{settings.FRONTEND_URL}/dashboard',
                'failure_url': f'{settings.FRONTEND_URL}/payment/failed',
                'metadata': {
                    'user_id': request.user.id,
                    'plan_type': plan_type,
                },
                'description': description,
            }
        )

        if not response.ok:
            return Response({'error': 'Failed to create checkout'}, status=500)

        data = response.json()

        Payment.objects.create(
            user=request.user,
            checkout_id=data['id'],
            amount=amount,
            status='pending',
            description=description,
        )

        return Response({
            'checkout_url': data['checkout_url'],
            'checkout_id': data['id'],
        })


class SubscriptionStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'is_active_subscription': user.is_active_subscription,
            'roles': list(user.roles.values_list('name', flat=True)),
        })

from django.contrib.auth import get_user_model

User = get_user_model()
"""
class CreateCheckoutView(APIView):
    permission_classes = []  # No authentication required

    def post(self, request):
        amount = request.data.get('amount')
        description = request.data.get('description', '')

        if not amount:
            return Response({'error': 'Amount required'}, status=400)

        # Get user with ID 34
        try:
            user = User.objects.get(id=34)
        except User.DoesNotExist:
            return Response({'error': 'User with ID 34 not found'}, status=404)

        response = requests.post(
            f'{settings.CHARGILY_BASE_URL}/checkouts',
            headers={
                'Authorization': f'Bearer {settings.CHARGILY_API_KEY}',
                'Content-Type': 'application/json',
            },
            json={
                'amount': int(amount),
                'currency': 'dzd',
                'success_url': f'{settings.FRONTEND_URL}/payment/success',
                'failure_url': f'{settings.FRONTEND_URL}/payment/failed',
                'metadata': {
                    'user_id': user.id,  # Now using user ID 34
                    'description': description,
                },
                'description': description,
            }
        )

        if not response.ok:
            return Response({'error': 'Failed to create checkout'}, status=500)

        data = response.json()

        Payment.objects.create(
            user=user,  # Using user ID 34 instead of request.user
            checkout_id=data['id'],
            amount=amount,
            status='pending',
            description=description,
        )

        return Response({
            'checkout_url': data['checkout_url'],
            'checkout_id': data['id'],
        })
"""
@csrf_exempt
@require_POST
def chargily_webhook(request):
    from django.http import HttpResponse, JsonResponse
    
    signature = request.headers.get('signature')
    payload = request.body.decode('utf-8')

    if not signature:
        return HttpResponse(status=400)

    computed_signature = hmac.new(
        settings.CHARGILY_API_KEY.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, computed_signature):
        return HttpResponse(status=403)

    event = json.loads(payload)
    checkout = event.get('data', {})
    checkout_id = checkout.get('id')
    metadata = checkout.get('metadata', {})

    if event['type'] == 'checkout.paid':
        payment = Payment.objects.filter(checkout_id=checkout_id).first()
        if payment:
            payment.status = 'paid'
            payment.save()
            
            user_id = metadata.get('user_id')
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                    user.is_active_subscription = True
                    user.save()
                except User.DoesNotExist:
                    pass

    elif event['type'] == 'checkout.failed':
        Payment.objects.filter(checkout_id=checkout_id).update(status='failed')

    return JsonResponse({}, status=200)

