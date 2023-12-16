import unittest
from unittest.mock import patch
from src.handle_data import (
    read_data,
    write_data,
    edit_data,
    delete_data,
    db_init,
    generate_key,
    _encrypt,
    _decrypt,
    change_login_password,
)
import os


class TestDB(unittest.TestCase):
    """
    Run the tests with

    python3 -m unittest discover -s tests
    """

    def setUp(self):
        self.db_name = "db_for_tests_for_password_manager.db"
        self.patcher = patch('src.handle_data.DB_NAME', new=self.db_name)
        self.mock_db_name = self.patcher.start()
        self.iterations_patcher = patch(
            'src.handle_data.KEY_ITERATIONS', new=1)
        self.iterations_patcher.start()
        db_init()
        self.password = "secret"
        self.username = "test_user"
        self.key = generate_key(self.password, self.username)
        write_data(self.key, "base", "base_password", "base_username")

    def tearDown(self):
        # Stop the patcher to clean up and remove the test db
        self.patcher.stop()
        os.remove(self.db_name)

    def test_read_data(self):
        data, count = read_data(self.key)
        self.assertEqual(1, count)
        self.assertListEqual(
            [
                {
                    'id': 1,
                    'description': 'base',
                    'password': 'base_password',
                    'username': 'base_username',
                },
            ],
            data
        )

    def test_write_data(self):
        write_data(self.key, "testing", "some_password", "username")
        data, count = read_data(self.key)
        self.assertEqual(2, count)
        self.assertListEqual(
            [
                {
                    'id': 1,
                    'description': 'base',
                    'password': 'base_password',
                    'username': 'base_username',
                },
                {
                    'id': 2,
                    'description': 'testing',
                    'password': 'some_password',
                    'username': 'username',
                },
            ],
            data
        )

    def test_remove_data(self):
        data, count = read_data(self.key)
        self.assertEqual(1, len(data))
        self.assertEqual(1, count)

        delete_data(self.key, 1)

        data, _ = read_data(self.key)
        self.assertListEqual(
            [],
            data
        )

    def test_edit_data(self):
        data, count = read_data(self.key)
        self.assertEqual(1, count)

        self.assertListEqual(
            [
                {
                    'id': 1,
                    'description': 'base',
                    'password': 'base_password',
                    'username': 'base_username',
                },
            ],
            data
        )
        edit_data(
            self.key, 1,
            "edited_base",
            'base_password',
            'base_username'
        )
        data, count = read_data(self.key)
        self.assertEqual(1, count)
        self.assertListEqual(
            [
                {
                    'id': 1,
                    'description': 'edited_base',
                    'password': 'base_password',
                    'username': 'base_username',
                },
            ],
            data
        )

    def test_encrypt_decrypt(self):
        plain_text = "some_message"
        encrypted_text = _encrypt(
            plain_text, self.key, "static_vector111".encode())
        self.assertEqual(
            b'LqmqHlr5Nu6+ra6owJoPuCqHelEuOXMxQxe5Zis013s=',
            encrypted_text
        )
        decrypted_text = _decrypt(
            encrypted_text, self.key, "static_vector111".encode())
        self.assertEqual(
            "some_message",
            decrypted_text
        )

    def test_decrypt_with_wrong_password(self):
        """
        Raises a Value error when decrypting with wrong password
        """
        plain_text = "some_message"
        encrypted_text = _encrypt(
            plain_text, self.key, "static_vector111".encode())
        self.assertEqual(
            b'LqmqHlr5Nu6+ra6owJoPuCqHelEuOXMxQxe5Zis013s=',
            encrypted_text
        )
        wrong_key = generate_key("wrong_secret", self.username)

        with self.assertRaises(ValueError) as context:
            _decrypt(encrypted_text, wrong_key, "static_vector111".encode())

        self.assertEqual(str(context.exception), "Invalid padding bytes.")

    def test_decrypt_with_wrong_username(self):
        """
        Raises a ValueError if they key for decrypt does not match the encrypt key
        """
        plain_text = "some_message"
        encrypted_text = _encrypt(
            plain_text, self.key, "static_vector111".encode())
        self.assertEqual(
            b'LqmqHlr5Nu6+ra6owJoPuCqHelEuOXMxQxe5Zis013s=',
            encrypted_text
        )
        wrong_key = generate_key(self.password, "wrong_username")

        with self.assertRaises(ValueError) as context:
            _decrypt(encrypted_text, wrong_key, "static_vector111".encode())

        self.assertEqual(str(context.exception), "Invalid padding bytes.")

    def test_init_vector(self):
        """
        Test init vectors produce different cipher text.

        Initialize vector should be random and while identical vectors produce the same cipher text,
        the same message should have a different cipher text when the initialize vectors are even slightly different.
        """
        plain_text = "some_message"
        encrypted_text = _encrypt(
            plain_text, self.key, "static_vector111".encode())
        encrypted_text2 = _encrypt(
            plain_text, self.key, "static_vector112".encode())
        self.assertNotEqual(encrypted_text, encrypted_text2)
        self.assertEqual(
            b'LqmqHlr5Nu6+ra6owJoPuCqHelEuOXMxQxe5Zis013s=',
            encrypted_text
        )
        self.assertEqual(
            b'WBU8MSRrRjtzJcn1Zs8aGTEn/KcWMtEgFxSgP0hcm74=',
            encrypted_text2
        )

    def test_change_master_password(self):
        new_password = "new_secret"
        new_username = "new_username"

        data, count = read_data(self.key)
        self.assertEqual(1, len(data))
        self.assertEqual(1, count)

        ok = change_login_password(
            self.username, self.password, new_username, new_password)
        self.assertTrue(ok)

        new_key = generate_key(new_password, new_username)
        data, _ = read_data(new_key)
        self.assertListEqual(
            [
                {
                    "id": 1,
                    "description": "base",
                    "password": "base_password",
                    "username": "base_username"
                }
            ],
            data
        )

        # read with old key
        data = read_data(self.key)
        self.assertListEqual(
            [],
            data
        )


if __name__ == '__main__':
    unittest.main()
