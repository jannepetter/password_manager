import unittest
from src.handle_data import (
    validate_password,
    validate_username,
    )

class TestDB(unittest.TestCase):
    """
    Run the tests with

    python3 -m unittest discover -s tests
    """

    def test_too_short_password(self):
        """
        Test password validation with too short password.
        """
        password = "Short1!"
        score, errors = validate_password(password)
        self.assertEqual(score,0)
        self.assertListEqual(
            ['Required password length >= 12 chars.'],
            errors,
        )
    def test_low_complexity_password(self):
        """
        Test password validation with low complexity password.
        """
        password = "password1234"
        score, errors = validate_password(password)
        self.assertEqual(score,0)
        self.assertListEqual(
            [
                'Uppercase char required in password.',
                'Special char required in password: !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
            ],
            errors,
        )

    def test_common_password(self):
        """
        Test password validation with common password.
        """
        password = "Password1234!"
        score, errors = validate_password(password)
        self.assertEqual(score,1)
        self.assertListEqual(
            [
                'Add another word or two. Uncommon words are better.',
                'Capitalization doesn\'t help very much.',
                'This is similar to a commonly used password.',
                'Complexity score 1 is below the required 4. Your password is too predictable.'
                ],
            errors,
        )

    def test_username(self):
        """
        Username is used in master key creation and has a minimum required length.
        """
        errors = validate_username("usr")
        self.assertListEqual(
            ['Minimum length for username is 4'],
            errors,
        )

