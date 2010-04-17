# -*- coding: utf-8 -*-
import random
import string
import unittest

from django.db import connection
from django.db import models

from fields import EncryptedCharField, PickleField


class EncObject(models.Model):
    max_password = 20
    password = EncryptedCharField(max_length=max_password)

class PickleObject(models.Model):
    name = models.CharField(max_length=16)
    data = PickleField()

class RandomChoiceMonkeyPatch():
    def __init__(self):
        def patched_choice(sequence):
            """Instead of choosing a random char from sequence, cycle through them order."""
            patched_choice.index = (patched_choice.index + 1) % len(sequence)
            return sequence[patched_choice.index]
        patched_choice.index = 0
        self.old_choice = random.choice
        random.choice = patched_choice  # monkey patch!

    def remove(self):
        # Remove monkey patch
        random.choice = self.old_choice


class RandomChoiceMonkeyPatchTests(unittest.TestCase):
    def testMonkeyPatch(self):
        """
        Test that we can make random.choice() provide different values, rather than truly random ones.
        """
        patch = RandomChoiceMonkeyPatch()
        # If we get len(choices) from patched_choice(), they should be unique,
        # which they probably wouldn't be if they were truly random.
        choices = string.printable
        max = len(choices)
        char_set = set([random.choice(choices) for index in range(max)])
        self.assertEqual(max, len(char_set))
        # Remove monkey patch
        patch.remove()
        # Make sure it works the old way now.
        char_set = set([random.choice(choices) for index in range(max)])
        # There are 100 chars in string.printable.
        # Out of 100 choices, there should be at least one dupe.
        # The chance of randomly generating 100 unique characters is about 10^-42 (100!/(100^100)).
        # I'm ok with that.  If this test fails, buy a lottery ticket.  ;)
        self.assertTrue(max > len(char_set))


class EncryptTests(unittest.TestCase):
    def setUp(self):
        EncObject.objects.all().delete()

    def testEncryption(self):
        """
        Test that the database values are actually encrypted.
        """
        password = 'this is a password!!'  # 20 chars
        obj = EncObject(password = password)
        obj.save()
        # The value from the retrieved object should be the same...
        obj = EncObject.objects.get(id=obj.id)
        self.assertEqual(password, obj.password)
        # ...but the value in the database should not
        encrypted_password = self._get_encrypted_password(obj.id)
        self.assertNotEqual(encrypted_password, password)
        self.assertTrue(encrypted_password.startswith('$AES$'))

    def testMaxFieldLength(self):
        password = 'a' * EncObject.max_password
        obj = EncObject(password = password)
        obj.save()
        obj = EncObject.objects.get(id=obj.id)
        self.assertEqual(password, obj.password)

    def testFieldTooLong(self):
        password = 'a' * (EncObject.max_password + 1)
        obj = EncObject(password = password)
        # FIXME:  We should get an exception here.
        self.assertEqual(password, obj.password)
        # self.assertRaises(Exception, obj.save)

    def testUTF8(self):
        password = u'совершенно секретно'
        obj = EncObject(password = password)
        obj.save()
        obj = EncObject.objects.get(id=obj.id)
        self.assertEqual(password, obj.password)
    
    def testConsistentEncryption(self):
        """
        The same password should not encrypt the same way twice.
        Check different lengths.
        """
        # Monkey patch to guarantee that padding for each field will be different,
        # which it might not be (1/100 chance) if it were truly random.
        patch = RandomChoiceMonkeyPatch()
        for pwd_length in range(1,15) + range(17,21):  # 1-14, 17-20 inclusive
            enc_pwd_1, enc_pwd_2 = self._get_two_passwords(pwd_length)
            self.assertNotEqual(enc_pwd_1, enc_pwd_2)
        # 15 or 16-character strings will encrypt the same way consistently
        # FIXME:  This is not a good thing.
        enc_pwd_1, enc_pwd_2 = self._get_two_passwords(15)
        self.assertEqual(enc_pwd_1, enc_pwd_2)
        enc_pwd_1, enc_pwd_2 = self._get_two_passwords(16)
        self.assertEqual(enc_pwd_1, enc_pwd_2)
        patch.remove()

    ### Utility methods for tests ###

    def _get_encrypted_password(self, id):
        cursor = connection.cursor()
        cursor.execute("select password from django_fields_encobject where id = %s", [id,])
        passwords = map(lambda x: x[0], cursor.fetchall())
        self.assertEqual(len(passwords), 1)  # only one
        return passwords[0]

    def _get_two_passwords(self, pwd_length):
        password = 'a' * pwd_length  # 'a', 'aa', ...
        obj_1 = EncObject(password = password)
        obj_1.save()
        obj_2 = EncObject(password = password)
        obj_2.save()
        # The encrypted values in the database should be different.
        # There's a chance they'll be the same, but it's small.
        enc_pwd_1 = self._get_encrypted_password(obj_1.id)
        enc_pwd_2 = self._get_encrypted_password(obj_2.id)
        return enc_pwd_1, enc_pwd_2

class TestPickleField(unittest.TestCase):
    def setUp(self):
        PickleObject.objects.all().delete()

    def test_not_string_data(self):
        items = [
            'Item 1', 'Item 2', 'Item 3', 'Item 4', 'Item 5'
        ]

        obj = PickleObject.objects.create(name='default', data=items)
        self.assertEqual(PickleObject.objects.count(), 1)

        self.assertEqual(obj.data, items)

        obj = PickleObject.objects.get(name='default')
        self.assertEqual(obj.data, items)

    def test_string_and_unicode_data(self):
        DATA = (
            ('string', 'Simple string'),
            ('unicode', u'Simple unicode string'),
        )

        for name, data in DATA:
            obj = PickleObject.objects.create(name=name, data=data)
            self.assertEqual(obj.data, data)

        self.assertEqual(PickleObject.objects.count(), 2)

        for name, data in DATA:
            obj = PickleObject.objects.get(name=name)
            self.assertEqual(obj.data, data)
