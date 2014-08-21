from ctypes import *
from ctypes.wintypes import *

OBJ_CASE_INSENSITIVE = 0x00000040
KEY_ALL_ACCESS = 0xF003F
KEY_WOW64_64KEY = 0x0100
REG_OPTION_NON_VOLATILE = 0x00000000L

def NT_SUCCESS(status):
	if (status >= 0 and status <= 0x3FFFFFFF) or (status >= 0x40000000 and status <= 0x7FFFFFFF):
		return 1
	else:
		return 0

class UNICODE_STRING(Structure):
	_fields_ = [("Length", USHORT),
		    ("MaximumLength", USHORT),
		    ("Buffer", c_wchar_p)]

class OBJECT_ATTRIBUTES(Structure):
	_fields_ = [("Length", ULONG),
		    ("RootDirectory", HANDLE),
                    ("ObjectName", POINTER(UNICODE_STRING)),
                    ("Attributes", ULONG),
                    ("SecurityDescriptor", c_void_p),
                    ("SecurityQualityOfService", c_void_p)]

def InitializeObjectAttributes(p, n, a, r, s):
	p.Length = sizeof(OBJECT_ATTRIBUTES)
	p.RootDirectory = r
	p.Attributes = a
	p.ObjectName = n
	p.SecurityDescriptor = s
	p.SecurityQualityOfService = None

KeyNameBuffer = create_unicode_buffer("\\Registry\\Machine\\SOFTWARE\\")
NewKeyNameBuffer = create_unicode_buffer("a")
HiddenKeyNameBuffer = create_unicode_buffer(u"Can't touch me!".encode("UTF-16LE"))

KeyName = UNICODE_STRING()
ObjectAttributes = OBJECT_ATTRIBUTES()

KeyHandle = HANDLE()
Disposition = c_ulong()

windll.ntdll.RtlInitUnicodeString(byref(KeyName), pointer(KeyNameBuffer))

InitializeObjectAttributes(ObjectAttributes, pointer(KeyName), OBJ_CASE_INSENSITIVE, None, None)

status = windll.ntdll.NtCreateKey(byref(KeyHandle), KEY_ALL_ACCESS | KEY_WOW64_64KEY, pointer(ObjectAttributes), 0, None, REG_OPTION_NON_VOLATILE, byref(Disposition))

if not NT_SUCCESS(status):
    print "[!]Error: " + str(GetLastError())
    print "[!]Status: " + str(status)

print "[!]Disposition: " + str(Disposition.value)
######
Disposition = c_ulong()
newKeyName = UNICODE_STRING()
newObjectAttributes = OBJECT_ATTRIBUTES()
SysKeyHandle = HANDLE()

windll.ntdll.RtlInitUnicodeString(byref(newKeyName), pointer(NewKeyNameBuffer))

InitializeObjectAttributes(newObjectAttributes, pointer(newKeyName), OBJ_CASE_INSENSITIVE, KeyHandle, None)

status = windll.ntdll.NtCreateKey(byref(SysKeyHandle), KEY_ALL_ACCESS | KEY_WOW64_64KEY, pointer(newObjectAttributes), 0, None, REG_OPTION_NON_VOLATILE, byref(Disposition))

if not NT_SUCCESS(status):
    print "[!]Error: " + str(GetLastError())
    print "[!]Status: " + str(status)

print "[!]Disposition: " + str(Disposition.value)
######
Disposition = c_ulong()
HiddenKeyName = UNICODE_STRING()
HiddenObjectAttributes = OBJECT_ATTRIBUTES()
HiddenKeyHandle = HANDLE()

HiddenKeyName.Buffer = wstring_at(create_unicode_buffer(u'abc\0def'), 7)
HiddenKeyName.Length = 8

InitializeObjectAttributes(HiddenObjectAttributes, pointer(HiddenKeyName), OBJ_CASE_INSENSITIVE, SysKeyHandle, None)

status = windll.ntdll.NtCreateKey(byref(HiddenKeyHandle), KEY_ALL_ACCESS | KEY_WOW64_64KEY, pointer(HiddenObjectAttributes), 0, None, REG_OPTION_NON_VOLATILE, byref(Disposition))

if not NT_SUCCESS(status):
    print "[!]Error: " + str(GetLastError())
    print "[!]Status: " + str(status)
print "[!]Disposition: " + str(Disposition.value)

print 
windll.ntdll.NtDeleteKey(HiddenKeyHandle)
windll.ntdll.NtDeleteKey(SysKeyHandle)

