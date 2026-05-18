from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class RoleChoices(models.TextChoices):
    TEACHER = 'TEACHER', 'Teacher'
    STUDENT = 'STUDENT', 'Student'
    PARENT = 'PARENT', 'Parent'
    ADMIN = 'ADMIN', 'Admin'


class Role(models.Model):
    name = models.CharField(max_length=20, choices=RoleChoices.choices, unique=True)
    
    class Meta:
        db_table = 'roles'
        
    def __str__(self):
        return self.name


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, roles=None, **extra_fields):
        """
        Creates and saves a User with the given email, password, and roles.
        """
        if not email:
            raise ValueError('The Email must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        
        if roles:
            role_objs = []
            for role_name in roles:
                role_obj, _ = Role.objects.get_or_create(name=role_name)
                role_objs.append(role_obj)
            user.roles.set(role_objs)
            
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with role=ADMIN
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        user = self.create_user(email, password, roles=[RoleChoices.ADMIN], **extra_fields)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, max_length=255)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    roles = models.ManyToManyField(Role, related_name='users', blank=True)
    is_active = models.BooleanField(default=True)
    is_active_subscription = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, default='')
    phone_verified = models.BooleanField(default=False)
    address = models.TextField(blank=True)
    date_of_birth = models.DateField(null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'users'

    def __str__(self):
        role_names = ", ".join([r.name for r in self.roles.all()]) if self.pk else ""
        return f"{self.email} ({role_names})"
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email


class TeacherProfile(models.Model):
    """
    Teacher profile linked to User
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='teacher_profile')
    specialization = models.CharField(max_length=255, blank=True)
    hire_date = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'teachers'

    def __str__(self):
        return f"Teacher: {self.user.get_full_name}"

    @property
    def get_full_name(self):
        return self.user.get_full_name


class ParentProfile(models.Model):
    """
    Parent profile linked to User
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='parent_profile')
    occupation = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = 'parents'

    def __str__(self):
        return f"Parent: {self.user.get_full_name}"

    @property
    def get_full_name(self):
        return self.user.get_full_name


class StudentProfile(models.Model):
    """
    Student profile linked to User
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile', null=True, blank=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    enrollment_date = models.DateField(null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.BooleanField(default=True, help_text="True for male, False for female")
    scholarship_holder = models.BooleanField(default=False, help_text="True if has scholarship")
    parent_user = models.ForeignKey(
        ParentProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='children'
    )

    class Meta:
        db_table = 'students'

    @property
    def get_full_name(self):
        if self.first_name or self.last_name:
            return f"{self.first_name or ''} {self.last_name or ''}".strip()
        return self.user.get_full_name if self.user else "Unknown"

    @property
    def enrollment_age(self):
        dob = self.date_of_birth or (self.user.date_of_birth if self.user else None)
        if not dob or not self.enrollment_date:
         return None
        age = self.enrollment_date.year - dob.year
        if (self.enrollment_date.month, self.enrollment_date.day) < (dob.month, dob.day):
            age -= 1
        return age
    
class Level(models.Model):
    """
    Level model - represents grades from primary school to high school
    """
    name = models.CharField(max_length=100)  # e.g., "Grade 1", "Grade 10", "Baccalaureate"
    
    class Meta:
        db_table = 'levels'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class ClassTeacher(models.Model):
    """
    Explicit through model for Class-Teacher relationship with optional level
    """
    class_obj = models.ForeignKey(
        'Class',
        on_delete=models.CASCADE,
        related_name='class_teachers',
        db_column='class_id'
    )
    teacher = models.ForeignKey(
        'TeacherProfile',
        on_delete=models.CASCADE,
        related_name='class_teachers',
        db_column='teacher_id'
    )
    level = models.ForeignKey(
        'Level',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='class_teachers',
        db_column='level_id'
    )

    class Meta:
        db_table = 'classes_teachers'
        unique_together = ['class_obj', 'teacher', 'level']

    def __str__(self):
        return f"{self.class_obj.name} - {self.teacher.user.get_full_name}"


class Class(models.Model):
    """
    Class model - taught by multiple Teachers, attended by many Students
    """
    name = models.CharField(max_length=100)  # e.g., "Mathematics", "Physics"
    description = models.TextField(blank=True)
    teachers = models.ManyToManyField(
        TeacherProfile,
        through='ClassTeacher',
        related_name='classes_taught',
        blank=True
    )
    levels = models.ManyToManyField('Level', related_name='classes', blank=True)

    class Meta:
        db_table = 'classes'
        verbose_name_plural = 'Classes'

    def __str__(self):
        teacher_names = ", ".join([t.user.get_full_name for t in self.teachers.all()]) if self.teachers.exists() else "No teachers"
        return f"{self.name} (Teachers: {teacher_names})"


class EnrollmentStatus(models.TextChoices):
    PENDING = 'PENDING', 'Pending'
    APPROVED = 'APPROVED', 'Approved'
    REJECTED = 'REJECTED', 'Rejected'


class Enrollment(models.Model):
    """
    Enrollment requests - links students to class-teacher assignments with approval workflow
    """
    student = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    class_teacher = models.ForeignKey(
        'ClassTeacher',
        on_delete=models.CASCADE,
        related_name='enrollment_requests'
    )
    status = models.CharField(
        max_length=20,
        choices=EnrollmentStatus.choices,
        default=EnrollmentStatus.PENDING
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'enrollment'
        unique_together = ['student', 'class_teacher']
        ordering = ['-requested_at']

    def __str__(self):
        return f"{self.student.user.get_full_name} - {self.class_teacher.class_obj.name} ({self.status})"


class Skill(models.Model):
    """
    Skill model - represents skills that exercises develop in students
    """
    name = models.CharField(max_length=255, unique=True)
    skill_importance = models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High')], default=2)
    levels = models.ManyToManyField('Level', related_name='skills', blank=True)

    class Meta:
        db_table = 'skills'
        verbose_name_plural = 'Skills'

    def __str__(self):
        return self.name


class Exercise(models.Model):
    """
    Exercise model - stores file paths uploaded by teachers
    """
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    file_path = models.FileField(upload_to='exercises/')
    teacher = models.ForeignKey(
        TeacherProfile,
        on_delete=models.CASCADE,
        related_name='uploaded_exercises'
    )
    related_class = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='exercises',
        null=True,
        blank=True
    )
    level = models.ForeignKey(
        Level,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='exercises',
        db_column='level_id'
    )
    skills = models.ManyToManyField(
        Skill,
        related_name='exercises',
        blank=True
    )
    students = models.ManyToManyField(
        StudentProfile,
        related_name='assigned_exercises',
        blank=True,
        db_table='student_exercises'
    )
    due_date = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'exercises'

    def __str__(self):
        return f"{self.title} by {self.teacher.user.get_full_name}"


class ExerciseSubmission(models.Model):
    """
    Tracks student submissions for exercises
    """
    student = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name='submissions'
    )
    exercise = models.ForeignKey(
        Exercise,
        on_delete=models.CASCADE,
        related_name='submissions'
    )
    submission_file = models.FileField(upload_to='submissions/', null=True, blank=True)
    submission_text = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    grade = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    feedback = models.TextField(blank=True)
    graded_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'exercise_submissions'
        unique_together = ['student', 'exercise']
        ordering = ['-submitted_at']
    
    def __str__(self):
        return f"{self.student.user.get_full_name} - {self.exercise.title}"


class Message(models.Model):
    """
    Message model for Teacher-Parent chat
    """
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_messages'
    )
    receiver = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_messages'
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        db_table = 'messages'
        ordering = ['created_at']

    def __str__(self):
        return f"From {self.sender.get_full_name} to {self.receiver.get_full_name}"


class Announcement(models.Model):
    """
    Announcement model for Teacher announcements
    """
    teacher = models.ForeignKey(
        TeacherProfile,
        on_delete=models.CASCADE,
        related_name='announcements'
    )
    related_class = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='announcements',
        null=True,
        blank=True
    )
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'announcements'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} by {self.teacher.user.get_full_name}"


class Attendance(models.Model):
    """
    Attendance model for tracking student attendance
    """
    ATTENDANCE_STATUS = [
        ('PRESENT', 'Present'),
        ('ABSENT', 'Absent'),
    ]
    
    student = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name='attendance_records'
    )
    related_class = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='attendance_records'
    )
    date = models.DateField()
    status = models.CharField(max_length=10, choices=ATTENDANCE_STATUS)
    marked_by = models.ForeignKey(
        TeacherProfile,
        on_delete=models.CASCADE,
        related_name='attendance_marked'
    )
    marked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'attendance'
        ordering = ['-date']
        unique_together = ['student', 'related_class', 'date']

    def __str__(self):
        return f"{self.student.user.get_full_name} - {self.status} on {self.date}"


class Notification(models.Model):
    """
    Notification model for student/parent notifications
    """
    NOTIFICATION_TYPES = [
        ('EXERCISE', 'Exercise'),
        ('ABSENCE', 'Absence'),
        ('ANNOUNCEMENT', 'Announcement'),
        ('GRADE', 'Grade'),
    ]
    
    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.recipient.get_full_name}: {self.type}"


class ContactUs(models.Model):
    """
    Contact Us model for storing messages from users (landing page)
    """
    name = models.CharField(max_length=255)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        db_table = 'contact_us'
        ordering = ['-created_at']

def __str__(self):
        return f"Message from {self.name} - {self.email}"


class PhoneOTP(models.Model):
    phone_number = models.CharField(max_length=20)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    class Meta:
        db_table = 'phone_otp'
        ordering = ['-created_at']

    def __str__(self):
        return f"OTP for {self.phone_number}"


class Payment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    checkout_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payments'

    def __str__(self):
        return f"Payment {self.checkout_id} - {self.amount} DZD ({self.status})"

