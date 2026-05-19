from rest_framework import serializers
from .models import User, TeacherProfile, ParentProfile, StudentProfile, Class, Exercise, ExerciseSubmission, Message, Announcement, Attendance, Notification, Skill, Enrollment, EnrollmentStatus


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    roles = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name'
    )
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'roles', 'is_active', 'phone_number', 'address', 'date_of_birth']
        read_only_fields = ['id', 'roles']


class TeacherSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = TeacherProfile
        fields = ['id', 'user', 'full_name', 'specialization', 'hire_date']
        read_only_fields = ['id', 'user']


class ParentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    
    class Meta:
        model = ParentProfile
        fields = ['id', 'user', 'full_name', 'occupation', 'children']
        read_only_fields = ['id', 'user', 'children']


class StudentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    parent_name = serializers.CharField(source='parent_user.get_full_name', read_only=True)
    enrollment_age = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = StudentProfile
        fields = ['id', 'user', 'full_name', 'date_of_birth', 'enrollment_date', 'parent_user', 'parent_name', 'gender', 
                  'scholarship_holder', 'enrollment_age']
        read_only_fields = ['id', 'user', 'parent_name', 'enrollment_age']


class ClassSerializer(serializers.ModelSerializer):
    teacher_name = serializers.SerializerMethodField()
    teachers = serializers.SerializerMethodField()
    student_count = serializers.SerializerMethodField()
    students = serializers.SerializerMethodField()
    enrollment_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Class
        fields = ['id', 'name', 'description', 'teachers', 'teacher_name', 'students', 'student_count', 'enrollment_status']
        read_only_fields = ['id']
    
    def get_teacher_name(self, obj):
        teachers = obj.teachers.all()
        if teachers.exists():
            return ", ".join([t.user.get_full_name for t in teachers])
        return "No teachers"
    
    def get_teachers(self, obj):
        return [{'id': t.id, 'name': t.user.get_full_name, 'class_teacher_id': ct.id, 'level': ct.level.name if ct.level else None} for ct in obj.class_teachers.all() for t in [ct.teacher]]
    
    def get_student_count(self, obj):
        return obj.class_teachers.count()
    
    def get_students(self, obj):
        enrollments = Enrollment.objects.filter(class_teacher__class_obj=obj, status=EnrollmentStatus.APPROVED).select_related('student__user')
        return [{'id': e.student.id, 'user_id': e.student.user_id, 'full_name': e.student.get_full_name} for e in enrollments]
    
    def get_enrollment_status(self, obj):
        request = self.context.get('request')
        student_id_from_context = self.context.get('student_id')
        
        if not request or not request.user:
            return None
        
        try:
            # If student_id is passed in context (parent viewing as child), use that
            if student_id_from_context:
                student = StudentProfile.objects.get(id=student_id_from_context)
            else:
                student = StudentProfile.objects.get(user=request.user)
            enrollment = Enrollment.objects.filter(student=student, class_teacher__class_obj=obj).first()
            if enrollment:
                return {
                    'status': enrollment.status,
                    'requested_at': enrollment.requested_at.isoformat() if enrollment.requested_at else None,
                    'responded_at': enrollment.responded_at.isoformat() if enrollment.responded_at else None
                }
        except StudentProfile.DoesNotExist:
            pass
        return None


class EnrollmentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.user.get_full_name', read_only=True)
    class_name = serializers.CharField(source='class_teacher.class_obj.name', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Enrollment
        fields = ['id', 'student', 'student_name', 'class_teacher', 'class_name', 'teacher_name', 'status', 'requested_at', 'responded_at']
        read_only_fields = ['id', 'requested_at']
    
    def get_teacher_name(self, obj):
        return obj.class_teacher.teacher.user.get_full_name


class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = ['id', 'name', 'skill_importance']


class ExerciseSerializer(serializers.ModelSerializer):
    teacher_name = serializers.CharField(source='teacher.get_full_name', read_only=True)
    class_name = serializers.CharField(source='related_class.name', read_only=True)
    file_url = serializers.SerializerMethodField()
    skills = serializers.SerializerMethodField()
    level = serializers.SerializerMethodField()
    
    class Meta:
        model = Exercise
        fields = ['id', 'title', 'description', 'file_path', 'file_url', 'teacher', 'teacher_name',
                  'related_class', 'class_name', 'due_date', 'skills', 'level']
        read_only_fields = ['id', 'teacher']
        
    def get_level(self, obj):
        if obj.level:
            return obj.level.name
        if obj.related_class and obj.teacher:
            from .models import ClassTeacher
            ct = ClassTeacher.objects.filter(class_obj=obj.related_class, teacher=obj.teacher).first()
            if ct and ct.level:
                return ct.level.name
        return None
    
    def get_skills(self, obj):
        return [{'id': s.id, 'name': s.name} for s in obj.skills.all()]
    
    def create(self, validated_data):
        skills_data = validated_data.pop('skills', [])
        exercise = Exercise.objects.create(**validated_data)
        if skills_data:
            exercise.skills.set(skills_data)
        return exercise
    
    def update(self, instance, validated_data):
        skills_data = validated_data.pop('skills', None)
        exercise = super().update(instance, validated_data)
        if skills_data is not None:
            exercise.skills.set(skills_data)
        return exercise
    
    def get_file_url(self, obj):
        if obj.file_path:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.file_path.url)
            return obj.file_path.url
        return None


class ExerciseSubmissionSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.get_full_name', read_only=True)
    exercise_title = serializers.CharField(source='exercise.title', read_only=True)
    submission_file_url = serializers.SerializerMethodField()
    exercise = serializers.PrimaryKeyRelatedField(queryset=Exercise.objects.all())
    
    class Meta:
        model = ExerciseSubmission
        fields = ['id', 'student', 'student_name', 'exercise', 'exercise_title',
                  'submission_file', 'submission_file_url', 'submission_text', 'submitted_at', 'grade', 'feedback', 'graded_at']
        read_only_fields = ['id', 'submitted_at', 'student', 'student_name', 'exercise_title', 'submission_file_url']
    
    def get_submission_file_url(self, obj):
        if obj.submission_file:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.submission_file.url)
            return obj.submission_file.url
        return None


class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.get_full_name', read_only=True)
    receiver_name = serializers.CharField(source='receiver.get_full_name', read_only=True)
    
    class Meta:
        model = Message
        fields = ['id', 'sender', 'sender_name', 'receiver', 'receiver_name', 'content', 'created_at', 'is_read']
        read_only_fields = ['id', 'sender', 'created_at', 'is_read']


class AnnouncementSerializer(serializers.ModelSerializer):
    teacher_name = serializers.CharField(source='teacher.get_full_name', read_only=True)
    class_name = serializers.CharField(source='related_class.name', read_only=True)
    
    class Meta:
        model = Announcement
        fields = ['id', 'title', 'content', 'teacher', 'teacher_name', 'related_class', 'class_name', 'created_at']
        read_only_fields = ['id', 'teacher', 'created_at']


class AttendanceSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.get_full_name', read_only=True)
    class_name = serializers.CharField(source='related_class.name', read_only=True)
    teacher_name = serializers.CharField(source='marked_by.get_full_name', read_only=True)
    
    class Meta:
        model = Attendance
        fields = ['id', 'student', 'student_name', 'related_class', 'class_name', 'date', 'status', 'marked_by', 'teacher_name', 'marked_at']
        read_only_fields = ['id', 'marked_by', 'marked_at']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'recipient', 'type', 'message', 'is_read', 'created_at']
        read_only_fields = ['id', 'recipient', 'created_at']
