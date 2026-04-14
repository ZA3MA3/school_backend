from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Teacher, Parent, Student, Class, Exercise, ExerciseSubmission, Skill


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'role', 'is_active', 'is_staff']
    list_filter = ['role', 'is_active', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['email']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Role', {'fields': ('role',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role', 'first_name', 'last_name'),
        }),
    )


@admin.register(Teacher)
class TeacherAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'phone_number', 'specialization']
    list_filter = ['specialization', 'is_active']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['email']


@admin.register(Parent)
class ParentAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'phone_number', 'occupation']
    list_filter = ['occupation', 'is_active']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['email']


@admin.register(Student)
class StudentAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'phone_number', 'parent_user', 'enrollment_date']
    list_filter = ['enrollment_date', 'is_active']
    search_fields = ['email', 'first_name', 'last_name', 'parent_user__email']
    ordering = ['email']


@admin.register(Class)
class ClassAdmin(admin.ModelAdmin):
    list_display = ['name', 'teacher']
    list_filter = ['teacher']
    search_fields = ['name', 'teacher__email', 'teacher__first_name', 'teacher__last_name']
    filter_horizontal = ['students']


@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ['title', 'teacher', 'related_class', 'due_date']
    list_filter = ['teacher', 'related_class', 'skills']
    search_fields = ['title', 'description', 'teacher__email']
    filter_horizontal = ['skills']


@admin.register(ExerciseSubmission)
class ExerciseSubmissionAdmin(admin.ModelAdmin):
    list_display = ['student', 'exercise', 'submitted_at', 'grade']
    list_filter = ['submitted_at', 'graded_at']
    search_fields = ['student__email', 'exercise__title']
    raw_id_fields = ['student', 'exercise']
