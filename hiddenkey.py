import sys
import logging

from typing import Optional

from ctypes import *
from ctypes.wintypes import *

logging.basicConfig(
    format='(%(asctime)s)[%(levelname)s]\t%(message)s',
    datefmt='%H:%M:%S',
    level=logging.INFO
)

# As defined by Windows
OBJ_CASE_INSENSITIVE = c_ulong(0x00000040)
KEY_ALL_ACCESS = 0xF003F
REG_OPTION_NON_VOLATILE = 0x00000000

NT_SUCCESS_RANGE = (0, 0x80000000)

# Constants used in
TARGET_KEY = r'\Registry\Machine\SOFTWARE\Target Key'

NAME_HIDDEN_KEY = 'Open me!\0'

logger = logging.getLogger('Create Hidden Registry Key')


class UnicodeString(Structure):

    _fields_ = [
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', c_wchar_p)
    ]


class ObjectAttributes(Structure):

    _fields_ = [
        ('Length', ULONG),
        ('RootDirectory', HANDLE),
        ('ObjectName', POINTER(UnicodeString)),
        ('Attributes', ULONG),
        ('SecurityDescriptor', c_void_p),
        ('SecurityQualityOfService', c_void_p)
    ]

    def __init__(
            self,
            root_directory: Optional[HANDLE],
            object_name: POINTER(UnicodeString),
    ):
        super().__init__(
            Length=sizeof(ObjectAttributes),
            RootDirectory=root_directory,
            ObjectName=object_name,
            Attributes=OBJ_CASE_INSENSITIVE,
            SecurityDescriptor=None,
            SecurityQualityOfService=None
        )


def call_zwcreatekey(
        name: UnicodeString,
        root_directory: Optional[HANDLE] = None
) -> Optional[HANDLE]:
    """
    :return: False if an error occurred, the handle otherwise.
    """

    key_handle = HANDLE()

    object_attributes = ObjectAttributes(
        root_directory=root_directory,
        object_name=pointer(name),
    )

    create_key_nt_status = windll.ntdll.ZwCreateKey(
        byref(key_handle),
        KEY_ALL_ACCESS,
        pointer(object_attributes),
        0,
        None,
        REG_OPTION_NON_VOLATILE,
        None,
    )

    if create_key_nt_status not in NT_SUCCESS_RANGE:
        return None

    return key_handle


if __name__ == '__main__':

    if not windll.Shell32.IsUserAnAdmin():
        logger.warning('This script should be run as admin! Exiting.')
        sys.exit()

    logger.info('Creating/Opening target key')
    target_key_name_buffer = create_unicode_buffer(TARGET_KEY)
    target_key_name = UnicodeString()
    windll.ntdll.RtlInitUnicodeString(
        byref(target_key_name),
        pointer(target_key_name_buffer)
    )

    target_key_handle = call_zwcreatekey(target_key_name)

    if target_key_handle is None:
        logger.warning('Error during creating/opening target key.')
        sys.exit()

    logger.info('Creating hidden key')
    hidden_key_name_buffer = create_unicode_buffer(NAME_HIDDEN_KEY)

    hidden_key_name = UnicodeString()
    hidden_key_name.Buffer = wstring_at(
        hidden_key_name_buffer,
        cdll.ntdll.wcslen(hidden_key_name_buffer) + 1
    )

    hidden_key_name.Length = \
        (cdll.ntdll.wcslen(hidden_key_name_buffer) + 1) * sizeof(c_wchar)

    hidden_key_handle = call_zwcreatekey(
        hidden_key_name,
        target_key_handle
    )

    if hidden_key_handle is None:
        logger.warning('Error during creating hidden key.')
        sys.exit()

    logger.info('Successfully created the hidden key.')

    input('\n[+] Press enter to delete the hidden key.')
    windll.ntdll.NtDeleteKey(hidden_key_handle)
    windll.ntdll.NtDeleteKey(target_key_handle)
