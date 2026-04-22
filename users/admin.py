from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Role, TeacherProfile, ParentProfile, StudentProfile, Class, Exercise, ExerciseSubmission, Skill


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name']


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'is_active', 'is_staff']
    list_filter = ['roles', 'is_active', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['email']
    filter_horizontal = ['roles', 'groups', 'user_permissions']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Roles', {'fields': ('roles',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'roles', 'first_name', 'last_name'),
        }),
    )


@admin.register(TeacherProfile)
class TeacherAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'specialization']
    list_filter = ['specialization']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']


@admin.register(ParentProfile)
class ParentAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'occupation']
    list_filter = ['occupation']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']


@admin.register(StudentProfile)
class StudentAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'parent_user', 'enrollment_date']
    list_filter = ['enrollment_date']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']


@admin.register(Class)
class ClassAdmin(admin.ModelAdmin):
    list_display = ['name', 'teacher']
    list_filter = ['teacher']
    search_fields = ['name', 'teacher__user__email', 'teacher__user__first_name']
    filter_horizontal = ['students']


@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ['name', 'skill_importance']
    search_fields = ['name']


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ['title', 'teacher', 'related_class', 'due_date']
    list_filter = ['teacher', 'related_class', 'skills']
    search_fields = ['title', 'description', 'teacher__user__email']
    filter_horizontal = ['skills']


@admin.register(ExerciseSubmission)
class ExerciseSubmissionAdmin(admin.ModelAdmin):
    list_display = ['student', 'exercise', 'submitted_at', 'grade']
    list_filter = ['submitted_at', 'graded_at']
    search_fields = ['student__user__email', 'exercise__title']
    raw_id_fields = ['student', 'exercise']

