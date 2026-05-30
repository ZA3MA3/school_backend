from django.urls import path
from .views import (LoginView, LogoutView, CurrentUserView, RefreshTokenView,
                   TeacherClassesView, TeacherExercisesView, StudentExercisesView,
                   TeacherEnrollmentsView,
                   StudentSubmissionView, ParentChildrenView, ParentSearchExercisesView, ParentAssignExerciseView, ParentSubmissionsView, DownloadExerciseView, PublicAllClassesView,
                   AllClassesView, StudentEnrollView, TeacherSubmissionsView,
                   DownloadSubmissionView, GradeSubmissionView, ChatContactsView,
                   ChatMessagesView, WSTicketView, TeacherAnnouncementView,
                   StudentAnnouncementView, ParentAnnouncementView, TeacherAttendanceView,
                   StudentAttendanceView, ParentAttendanceView, NotificationListView,
                   NotificationUnreadCountView, NotificationMarkReadView, ChatUnreadCountView,
                   SkillListView, StudentPredictionView, contact_view, SendOTPView, VerifyOTPView,
                   GoogleAuthView, TeacherProfileCreateView, ParentStudentCreateView,
                   PhoneLoginSendView, PhoneLoginVerifyView, GoogleLoginOnlyView,
                   CreateCheckoutView, chargily_webhook, SubscriptionStatusView,
                   AdminExercisesView, AdminExerciseModerationView)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    # Teacher endpoints
    path('teacher/classes/', TeacherClassesView.as_view(), name='teacher_classes'),
    path('teacher/enrollments/', TeacherEnrollmentsView.as_view(), name='teacher_enrollments'),
    path('teacher/exercises/', TeacherExercisesView.as_view(), name='teacher_exercises'),
    path('teacher/submissions/', TeacherSubmissionsView.as_view(), name='teacher_submissions'),
    path('teacher/announcements/', TeacherAnnouncementView.as_view(), name='teacher_announcements'),
    path('teacher/attendance/', TeacherAttendanceView.as_view(), name='teacher_attendance'),
    # Admin endpoints
    path('admin/exercises/', AdminExercisesView.as_view(), name='admin_exercises'),
    path('admin/exercises/moderate/', AdminExerciseModerationView.as_view(), name='admin_exercise_moderation'),
    # Student endpoints
    path('classes/', AllClassesView.as_view(), name='all_classes'),
    path('classes/public/', PublicAllClassesView.as_view(), name='public-classes'),
    path('student/enroll/', StudentEnrollView.as_view(), name='student_enroll'),
    path('student/exercises/', StudentExercisesView.as_view(), name='student_exercises'),
    path('student/submissions/', StudentSubmissionView.as_view(), name='student_submissions'),
    path('student/announcements/', StudentAnnouncementView.as_view(), name='student_announcements'),
    path('student/attendance/', StudentAttendanceView.as_view(), name='student_attendance'),
    # Parent endpoints
    path('parent/children/', ParentChildrenView.as_view(), name='parent_children'),
    path('parent/announcements/', ParentAnnouncementView.as_view(), name='parent_announcements'),
    path('parent/attendance/', ParentAttendanceView.as_view(), name='parent_attendance'),
    path('parent/exercises/search/', ParentSearchExercisesView.as_view(), name='parent_search_exercises'),
    path('parent/exercises/assign/', ParentAssignExerciseView.as_view(), name='parent_assign_exercise'),
    path('parent/submissions/', ParentSubmissionsView.as_view(), name='parent_submissions'),
    # File download
    path('exercises/<int:exercise_id>/download/', DownloadExerciseView.as_view(), name='download_exercise'),
    path('submissions/<int:submission_id>/download/', DownloadSubmissionView.as_view(), name='download_submission'),
    path('submissions/<int:submission_id>/grade/', GradeSubmissionView.as_view(), name='grade_submission'),
    # Chat endpoints
    path('chat/contacts/', ChatContactsView.as_view(), name='chat_contacts'),
    path('chat/messages/<int:contact_id>/', ChatMessagesView.as_view(), name='chat_messages'),
    path('chat/unread-count/', ChatUnreadCountView.as_view(), name='chat_unread_count'),
    # WebSocket ticket
    path('ws-ticket/', WSTicketView.as_view(), name='ws_ticket'),
    # Notification endpoints
    path('notifications/', NotificationListView.as_view(), name='notifications'),
    path('notifications/unread-count/', NotificationUnreadCountView.as_view(), name='notifications_unread_count'),
    path('notifications/<int:notification_id>/read/', NotificationMarkReadView.as_view(), name='notification_mark_read'),
    # Skills endpoint
    path('skills/', SkillListView.as_view(), name='skills'),
    # Prediction endpoint
    path('predict/student/<int:student_id>/', StudentPredictionView.as_view(), name='student_prediction'),
    # Contact Us endpoint
    path('contact/', contact_view, name='contact_us'),
    # OTP endpoints
    path('otp/send/', SendOTPView.as_view(), name='otp_send'),
    path('otp/verify/', VerifyOTPView.as_view(), name='otp_verify'),
    # Google Auth endpoint
    path('auth/google/', GoogleAuthView.as_view(), name='google_auth'),
    # Role selection endpoints
    path('profile/teacher/', TeacherProfileCreateView.as_view(), name='teacher_profile_create'),
    path('profile/parent/', ParentStudentCreateView.as_view(), name='parent_student_create'),
    # Phone login endpoints
    path('login/phone/send/', PhoneLoginSendView.as_view(), name='phone_login_send'),
    path('login/phone/verify/', PhoneLoginVerifyView.as_view(), name='phone_login_verify'),
    path('login/google/', GoogleLoginOnlyView.as_view(), name='google_login_only'),
    # Payment endpoints
    path('payments/checkout/', CreateCheckoutView.as_view(), name='create_checkout'),
    path('payments/webhook/', chargily_webhook, name='chargily_webhook'),
    path('payments/status/', SubscriptionStatusView.as_view(), name='subscription_status'),
]
