import binascii
import datetime
import random
import string

from django import forms
from django.db import models
from django.conf import settings
from django.utils.encoding import smart_str, force_unicode


USE_CPICKLE = getattr(settings, 'USE_CPICKLE', False)

if USE_CPICKLE:
    import cPickle as pickle
else:
    import pickle

class BaseEncryptedField(models.Field):
    '''This code is based on the djangosnippet #1095
       You can find the original at http://www.djangosnippets.org/snippets/1095/'''

    def __init__(self, *args, **kwargs):
        cipher = kwargs.pop('cipher', 'AES')
        try:
            imp = __import__('Crypto.Cipher', globals(), locals(), [cipher], -1)
        except:
            imp = __import__('Crypto.Cipher', globals(), locals(), [cipher])
        self.cipher = getattr(imp, cipher).new(settings.SECRET_KEY[:32])
        self.prefix = '$%s$' % cipher

        max_length = kwargs.get('max_length', 40)
        self.unencrypted_length = max_length
        # always add at least 2 to the max_length: one for the null byte, one for padding
        max_length += 2
        mod = max_length % self.cipher.block_size
        if mod > 0:
            max_length += self.cipher.block_size - mod
        kwargs['max_length'] = max_length * 2 + len(self.prefix)

        models.Field.__init__(self, *args, **kwargs)

    def _is_encrypted(self, value):
        return isinstance(value, basestring) and value.startswith(self.prefix)

    def _get_padding(self, value):
        # We always want at least 2 chars of padding (including zero byte),
        # so we could have up to block_size + 1 chars.
        mod = (len(value) + 2) % self.cipher.block_size
        return self.cipher.block_size - mod + 2


    def to_python(self, value):
        if self._is_encrypted(value):
            return force_unicode(
                self.cipher.decrypt(
                    binascii.a2b_hex(value[len(self.prefix):])
                ).split('\0')[0]
            )
        return value

    def get_db_prep_value(self, value):
        value = smart_str(value)

        if value is not None and not self._is_encrypted(value):
            padding  = self._get_padding(value)
            if padding > 0:
                value += "\0" + ''.join([random.choice(string.printable) for index in range(padding-1)])
            value = self.prefix + binascii.b2a_hex(self.cipher.encrypt(value))
        return value

class EncryptedTextField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return 'TextField'

    def formfield(self, **kwargs):
        defaults = {'widget': forms.Textarea}
        defaults.update(kwargs)
        return super(EncryptedTextField, self).formfield(**defaults)

class EncryptedCharField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return "CharField"

    def formfield(self, **kwargs):
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super(EncryptedCharField, self).formfield(**defaults)

    def get_db_prep_value(self, value):
        if value is not None and not self._is_encrypted(value):
            if len(value) > self.unencrypted_length:
                raise ValueError("Field value longer than max allowed: " +
                    str(len(value)) + " > " + str(self.unencrypted_length))
        return super(EncryptedCharField, self).get_db_prep_value(value)


class BaseEncryptedDateField(BaseEncryptedField):
    # Do NOT define a __metaclass__ for this - it's abstract.
    # Had to make this an abstract parent to both EncryptedDateField and EncryptedDateTimeField.
    # Tried to make EncryptedDateTimeField subclass from EncryptedDateField,
    # and got a very opaque infinite recursion in contribute_to_class,
    # caused by having a parent with __metaclass__ = models.SubfieldBase.

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = self.max_raw_length
        super(BaseEncryptedDateField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return 'CharField'

    def formfield(self, **kwargs):
        defaults = {'widget': self.form_widget}
        defaults.update(kwargs)
        return super(BaseEncryptedDateField, self).formfield(**defaults)

    def to_python(self, value):
        # value is a date string in the format "YYYY:MM:DD"
        date_text = super(BaseEncryptedDateField, self).to_python(value)
        if isinstance(date_text, self.date_class):
            date_value = date_text
        else:
            date_value = self.date_class(*map(int, date_text.split(':')))
        return date_value

    # def get_prep_value(self, value):
    def get_db_prep_value(self, value):
        # value is a date_class.
        # We need to convert it to a string in the format "YYYY:MM:DD"
        date_text = value.strftime(self.save_format)
        return super(BaseEncryptedDateField, self).get_db_prep_value(date_text)


class EncryptedDateField(BaseEncryptedDateField):
    __metaclass__ = models.SubfieldBase
    form_widget = forms.DateInput
    save_format = "%Y:%m:%d"
    date_class = datetime.date
    max_raw_length = 10  # YYYY:MM:DD


# class EncryptedDateTimeField(BaseEncryptedField):
class EncryptedDateTimeField(BaseEncryptedDateField):
    # FIXME:  This should deal with time zones, but Python doesn't really either.
    __metaclass__ = models.SubfieldBase
    form_widget = forms.DateTimeInput
    save_format = "%Y:%m:%d:%H:%M:%S:%f"
    date_class = datetime.datetime
    max_raw_length = 26  # YYYY:MM:DD:hh:mm:ss:micros

#    def __init__(self, *args, **kwargs):
#        kwargs['max_length'] = self.max_raw_length
#        super(EncryptedDateTimeField, self).__init__(*args, **kwargs)
#
#    def get_internal_type(self):
#        return 'CharField'
#
#    def formfield(self, **kwargs):
#        defaults = {'widget': forms.DateTimeInput}
#        defaults.update(kwargs)
#        return super(EncryptedDateTimeField, self).formfield(**defaults)
#
#    def to_python(self, value):
#        # value is a datetime string in the format "YYYY:MM:DD:hh:mm:ss:micros"
#        datetime_text = super(EncryptedDateTimeField, self).to_python(value)
#        if isinstance(datetime_text, datetime.datetime):
#            datetime_value = datetime_text
#        else:
#            datetime_value = datetime.datetime(*map(int, datetime_text.split(':')))
#        return datetime_value
#
#    # def get_prep_value(self, value):
#    def get_db_prep_value(self, value):
#        # value is a datetime.datetime.
#        # We need to convert it to a string in the format "YYYY:MM:DD:hh:mm:ss:micros"
#        datetime_text = value.strftime("%Y:%m:%d:%H:%M:%S:%f")
#        return super(EncryptedDateTimeField, self).get_db_prep_value(datetime_text)


class PickleField(models.TextField):
    __metaclass__ = models.SubfieldBase

    editable = False
    serialize = False

    def get_db_prep_value(self, value):
        return pickle.dumps(value)

    def to_python(self, value):
        if not isinstance(value, basestring):
            return value

        # Tries to convert unicode objects to string, cause loads pickle from
        # unicode excepts ugly ``KeyError: '\x00'``.
        try:
            return pickle.loads(smart_str(value))
        # If pickle could not loads from string it's means that it's Python
        # string saved to PickleField.
        except ValueError:
            return value
