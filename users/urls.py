from django.urls import path
from .views import (LoginView, LogoutView, CurrentUserView, RefreshTokenView,
                   TeacherClassesView, TeacherExercisesView, StudentExercisesView,
                   StudentSubmissionView, ParentChildrenView, DownloadExerciseView,
                   AllClassesView, StudentEnrollView, TeacherSubmissionsView,
                   DownloadSubmissionView, GradeSubmissionView, ChatContactsView,
                   ChatMessagesView, WSTicketView, TeacherAnnouncementView,
                   StudentAnnouncementView, ParentAnnouncementView)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    # Teacher endpoints
    path('teacher/classes/', TeacherClassesView.as_view(), name='teacher_classes'),
    path('teacher/exercises/', TeacherExercisesView.as_view(), name='teacher_exercises'),
    path('teacher/submissions/', TeacherSubmissionsView.as_view(), name='teacher_submissions'),
    path('teacher/announcements/', TeacherAnnouncementView.as_view(), name='teacher_announcements'),
    # Student endpoints
    path('classes/', AllClassesView.as_view(), name='all_classes'),
    path('student/enroll/', StudentEnrollView.as_view(), name='student_enroll'),
    path('student/exercises/', StudentExercisesView.as_view(), name='student_exercises'),
    path('student/submissions/', StudentSubmissionView.as_view(), name='student_submissions'),
    path('student/announcements/', StudentAnnouncementView.as_view(), name='student_announcements'),
    # Parent endpoints
    path('parent/children/', ParentChildrenView.as_view(), name='parent_children'),
    path('parent/announcements/', ParentAnnouncementView.as_view(), name='parent_announcements'),
    # File download
    path('exercises/<int:exercise_id>/download/', DownloadExerciseView.as_view(), name='download_exercise'),
    path('submissions/<int:submission_id>/download/', DownloadSubmissionView.as_view(), name='download_submission'),
    path('submissions/<int:submission_id>/grade/', GradeSubmissionView.as_view(), name='grade_submission'),
    # Chat endpoints
    path('chat/contacts/', ChatContactsView.as_view(), name='chat_contacts'),
    path('chat/messages/<int:contact_id>/', ChatMessagesView.as_view(), name='chat_messages'),
    # WebSocket ticket
    path('ws-ticket/', WSTicketView.as_view(), name='ws_ticket'),
]
