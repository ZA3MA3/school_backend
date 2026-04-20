from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class Role(models.TextChoices):
    TEACHER = 'TEACHER', 'Teacher'
    STUDENT = 'STUDENT', 'Student'
    PARENT = 'PARENT', 'Parent'
    ADMIN = 'ADMIN', 'Admin'


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email, password, and role.
        """
        if not email:
            raise ValueError('The Email must be set')

        role = extra_fields.pop('role', None)
        if not role:
            raise ValueError('Role must be provided')

        email = self.normalize_email(email)
        user = self.model(email=email, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with role=ADMIN
        """
        extra_fields.setdefault('role', Role.ADMIN)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('role') != Role.ADMIN:
            raise ValueError('Superuser must have role=ADMIN.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, max_length=255)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=20, choices=Role.choices)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['role']

    class Meta:
        db_table = 'users'

    def __str__(self):
        return f"{self.email} ({self.role})"
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email


class Teacher(User):
    """
    Teacher inherits from User with additional fields
    """
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    specialization = models.CharField(max_length=255, blank=True)
    hire_date = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'teachers'

    def __str__(self):
        return f"Teacher: {self.get_full_name}"


class Parent(User):
    """
    Parent inherits from User with additional fields
    """
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    occupation = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = 'parents'

    def __str__(self):
        return f"Parent: {self.get_full_name}"


class Student(User):
    """
    Student inherits from User with additional fields
    """
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    parent_occupation = models.CharField(max_length=255, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    enrollment_date = models.DateField(null=True, blank=True)
    gender = models.BooleanField(default=True, help_text="True for male, False for female")
    scholarship_holder = models.BooleanField(default=False, help_text="True if has scholarship")
    parent_user = models.ForeignKey(
        Parent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='children'
    )

    class Meta:
        db_table = 'students'

    def __str__(self):
        return f"Student: {self.get_full_name}"
    
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
        Teacher,
        on_delete=models.CASCADE,
        related_name='classes_taught'
    )
    students = models.ManyToManyField(
        Student,
        related_name='enrolled_classes',
        blank=True
    )

    class Meta:
        db_table = 'classes'
        verbose_name_plural = 'Classes'

    def __str__(self):
        return f"{self.name} (Teacher: {self.teacher.get_full_name})"


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
        Teacher,
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
        return f"{self.title} by {self.teacher.get_full_name}"


class ExerciseSubmission(models.Model):
    """
    Tracks student submissions for exercises
    """
    student = models.ForeignKey(
        Student,
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
        return f"{self.student.get_full_name} - {self.exercise.title}"


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
        Teacher,
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
        return f"{self.title} by {self.teacher.get_full_name}"


class Attendance(models.Model):
    """
    Attendance model for tracking student attendance
    """
    ATTENDANCE_STATUS = [
        ('PRESENT', 'Present'),
        ('ABSENT', 'Absent'),
    ]
    
    student = models.ForeignKey(
        Student,
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
        Teacher,
        on_delete=models.CASCADE,
        related_name='attendance_marked'
    )
    marked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'attendance'
        ordering = ['-date']
        unique_together = ['student', 'related_class', 'date']

    def __str__(self):
        return f"{self.student.get_full_name} - {self.status} on {self.date}"


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
