from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class Role(models.TextChoices):
    TEACHER = 'TEACHER', 'Teacher'
    STUDENT = 'STUDENT', 'Student'
    PARENT = 'PARENT', 'Parent'
    ADMIN = 'ADMIN', 'Admin'


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        """
        Creates and saves a User with the given username, password, and role.
        """
        if not username:
            raise ValueError('The Username must be set')

        role = extra_fields.pop('role', None)
        if not role:
            raise ValueError('Role must be provided')

        user = self.model(username=username, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        """
        Creates and saves a superuser with role=ADMIN
        """
        extra_fields.setdefault('role', Role.ADMIN)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('role') != Role.ADMIN:
            raise ValueError('Superuser must have role=ADMIN.')

        return self.create_user(username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    role = models.CharField(max_length=20, choices=Role.choices)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['role']

    def __str__(self):
        return f"{self.username} ({self.role})"
