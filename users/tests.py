from django.test import TestCase
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from .models import User, RoleChoices


class EssentialTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

        # Create a teacher for testing
        self.teacher = User.objects.create_user(
            email='teacher1@example.com',
            password='teacher123',
            roles=[RoleChoices.TEACHER]
        )

        # Create a student for testing
        self.student = User.objects.create_user(
            email='student1@example.com',
            password='student123',
            roles=[RoleChoices.STUDENT]
        )

    # ============================================
    # TEST 1: User can be created
    # ============================================
    def test_1_create_user_successful(self):
        """TEST 1: Creating a user works correctly"""
        user = User.objects.create_user(
            email='newteacher@example.com',
            password='password123',
            roles=[RoleChoices.TEACHER]
        )

        self.assertEqual(user.email, 'newteacher@example.com')
        self.assertTrue(user.roles.filter(name=RoleChoices.TEACHER).exists())
        self.assertTrue(user.check_password('password123'))
        print(" TEST 1 PASSED: User creation works")

    # ============================================
    # TEST 2: Login with correct credentials
    # ============================================
    def test_2_login_with_valid_credentials(self):
        response = self.client.post('/api/users/login/', {
            'email': 'teacher1@example.com',
            'password': 'teacher123'
        })

        # Check response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check user data is returned
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'teacher1@example.com')

        # Check role is returned (roles is a list)
        self.assertIn('roles', response.data)
        self.assertIn('TEACHER', response.data['roles'])

        # Check cookies are set
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)

        print(" TEST 2 PASSED: Login with valid credentials works")


    # ============================================
    # TEST 3: Login with wrong password fails
    # ============================================
    def test_3_login_with_wrong_password_fails(self):
        response = self.client.post('/api/users/login/', {
            'email': 'teacher1@example.com',
            'password': 'wrongpassword'
        })

        # Should return 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Should have error message
        self.assertIn('detail', response.data)

        print(" TEST 3 PASSED: Wrong password is rejected")

    # ============================================
    # TEST 4: Login with non-existent user fails
    # ============================================
    def test_4_login_with_nonexistent_user_fails(self):
        response = self.client.post('/api/users/login/', {
            'email': 'doesnotexist@example.com',
            'password': 'somepassword'
        })

        # Should return 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        print(" TEST 4 PASSED: Non-existent user is rejected")

    # ============================================
    # TEST 5: All roles can login
    # ============================================
    def test_5_all_roles_can_login(self):
        # Create users for each role (check if they exist first)
        if not User.objects.filter(email='parent1@example.com').exists():
            User.objects.create_user(email='parent1@example.com', password='pass123', roles=[RoleChoices.PARENT])

        if not User.objects.filter(email='admin1@example.com').exists():
            User.objects.create_user(email='admin1@example.com', password='pass123', roles=[RoleChoices.ADMIN])

        # Test each role
        roles = [
            ('teacher1@example.com', 'teacher123', 'TEACHER'),
            ('student1@example.com', 'student123', 'STUDENT'),
            ('parent1@example.com', 'pass123', 'PARENT'),
            ('admin1@example.com', 'pass123', 'ADMIN')
        ]

        for email, password, expected_role in roles:
            response = self.client.post('/api/users/login/', {
                'email': email,
                'password': password
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('roles', response.data)  # ✅ Check roles exists
            self.assertIn(expected_role, response.data['roles'])  # ✅ Check role in list

        print(" TEST 5 PASSED: All 4 roles can login")

    # ============================================
    # TEST 6: Get current user when logged in
    # ============================================
    def test_6_get_current_user_when_authenticated(self):
        # Simulate being logged in
        self.client.force_authenticate(user=self.teacher)

        response = self.client.get('/api/users/me/')

        # Should return 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Should return user data
        self.assertEqual(response.data['email'], 'teacher1@example.com')
        self.assertIn('roles', response.data)  # ✅ Check roles exists
        self.assertIn('TEACHER', response.data['roles'])  # ✅ Check role in list
        self.assertIn('id', response.data)

        print(" TEST 6 PASSED: Can get current user when authenticated")

    # ============================================
    # TEST 7: Get current user without login fails
    # ============================================
    def test_7_get_current_user_without_authentication_fails(self):
        response = self.client.get('/api/users/me/')

        # Should return 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        print(" TEST 7 PASSED: Must be logged in to access /me/")

    # ============================================
    # TEST 8: Logout works
    # ============================================
    def test_8_logout_works(self):
        # First login
        login_response = self.client.post('/api/users/login/', {
            'email': 'teacher1@example.com',
            'password': 'teacher123'  # Use raw password
        })
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # Then logout
        logout_response = self.client.post('/api/users/logout/')

        # Should return 200 OK
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

        # Should have success message
        self.assertEqual(logout_response.data['detail'], 'Successfully logged out')

        print(" TEST 8 PASSED: Logout works")

    # ============================================
    # TEST 9: Login requires both email and password
    # ============================================
    def test_9_login_requires_email_and_password(self):
        # Missing password
        response1 = self.client.post('/api/users/login/', {
            'email': 'teacher1@example.com'
        })
        self.assertEqual(response1.status_code, status.HTTP_400_BAD_REQUEST)

        # Missing email
        response2 = self.client.post('/api/users/login/', {
            'password': 'teacher123'
        })
        self.assertEqual(response2.status_code, status.HTTP_400_BAD_REQUEST)

        # Empty data
        response3 = self.client.post('/api/users/login/', {})
        self.assertEqual(response3.status_code, status.HTTP_400_BAD_REQUEST)

        print(" TEST 9 PASSED: Login validates required fields")
