from django.test import TestCase
from django.urls import reverse
from apps.accounts.models import User


class LoginValidationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='analyst', password='correct-password')

    def test_wrong_password_shows_visible_validation_message(self):
        response = self.client.post(reverse('login'), {
            'username': 'analyst',
            'password': 'wrong-password',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Incorrect password. Please try again.')
        self.assertContains(response, 'role="alert"')
        self.assertContains(response, 'aria-invalid="true"')

    def test_unknown_username_shows_account_not_found_message(self):
        response = self.client.post(reverse('login'), {
            'username': 'missing-user',
            'password': 'anything',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No account was found with that username.')