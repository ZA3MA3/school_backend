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
    is_staff = models.BooleanField(default=False)

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
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
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
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
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
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile')
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    parent_occupation = models.CharField(max_length=255, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    enrollment_date = models.DateField(null=True, blank=True)
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

    def __str__(self):
        return f"Student: {self.user.get_full_name}"
    
    @property
    def get_full_name(self):
        return self.user.get_full_name
    
    @property
    def enrollment_age(self):
        if self.date_of_birth and self.enrollment_date:
            age = self.enrollment_date.year - self.date_of_birth.year
            if (self.enrollment_date.month, self.enrollment_date.day) < (self.date_of_birth.month, self.date_of_birth.day):
                age -= 1
            return age
        return None


class Class(models.Model):
    """
    Class model - taught by a Teacher, attended by many Students
    """
    name = models.CharField(max_length=100)  # e.g., "Mathematics", "Physics"
    description = models.TextField(blank=True)
    teacher = models.ForeignKey(
        TeacherProfile,
        on_delete=models.CASCADE,
        related_name='classes_taught'
    )

    class Meta:
        db_table = 'classes'
        verbose_name_plural = 'Classes'

    def __str__(self):
        return f"{self.name} (Teacher: {self.teacher.user.get_full_name})"


class EnrollmentStatus(models.TextChoices):
    PENDING = 'PENDING', 'Pending'
    APPROVED = 'APPROVED', 'Approved'
    REJECTED = 'REJECTED', 'Rejected'


class Enrollment(models.Model):
    """
    Enrollment requests - links students to classes with approval workflow
    """
    student = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    class_obj = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='enrollment_requests',
        db_column='class_id'
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
        unique_together = ['student', 'class_obj']
        ordering = ['-requested_at']

    def __str__(self):
        return f"{self.student.user.get_full_name} - {self.class_obj.name} ({self.status})"


class Skill(models.Model):
    """
    Skill model - represents skills that exercises develop in students
    """
    name = models.CharField(max_length=255, unique=True)
    skill_importance = models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High')], default=2)

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
    skills = models.ManyToManyField(
        Skill,
        related_name='exercises',
        blank=True
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

