from ctypes import *
from ctypes.wintypes import *
import sys

if not windll.Shell32.IsUserAnAdmin():
    print "[!] This script should be run as admin!"
    print "[!] Exiting."
    sys.exit()

OBJ_CASE_INSENSITIVE = 0x00000040
KEY_ALL_ACCESS = 0xF003F
KEY_WOW64_64KEY = 0x0100
REG_OPTION_NON_VOLATILE = 0x00000000L

disposition_output = [None, "Opened existing key.", "Created new key."]


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




##Opening target key
TargetKeyNameBuffer = create_unicode_buffer("\\Registry\\Machine\\SOFTWARE\\Target Key")

TargetKeyName = UNICODE_STRING()
TargetObjectAttributes = OBJECT_ATTRIBUTES()

TargetKeyHandle = HANDLE()
Disposition = c_ulong()

windll.ntdll.RtlInitUnicodeString(byref(TargetKeyName), pointer(TargetKeyNameBuffer))

InitializeObjectAttributes(TargetObjectAttributes, pointer(TargetKeyName), OBJ_CASE_INSENSITIVE, None, None)

status = windll.ntdll.NtCreateKey(byref(TargetKeyHandle), KEY_ALL_ACCESS | KEY_WOW64_64KEY, pointer(TargetObjectAttributes), 0, None, REG_OPTION_NON_VOLATILE, byref(Disposition))

if not NT_SUCCESS(status):
    print "[!] Error: " + str(GetLastError())
    sys.exit()

print "[+] " + disposition_output[Disposition.value]

##Creatign hidden key
hiddenkeyname = u"abc\0def"

Disposition = c_ulong()
HiddenKeyName = UNICODE_STRING()
HiddenObjectAttributes = OBJECT_ATTRIBUTES()
HiddenKeyHandle = HANDLE()

HiddenKeyName.Buffer = wstring_at(create_unicode_buffer(hiddenkeyname), len(hiddenkeyname))
HiddenKeyName.Length = len(hiddenkeyname) + 1

InitializeObjectAttributes(HiddenObjectAttributes, pointer(HiddenKeyName), OBJ_CASE_INSENSITIVE, TargetKeyHandle, None)

status = windll.ntdll.NtCreateKey(byref(HiddenKeyHandle), KEY_ALL_ACCESS | KEY_WOW64_64KEY, pointer(HiddenObjectAttributes), 0, None, REG_OPTION_NON_VOLATILE, byref(Disposition))

if not NT_SUCCESS(status):
    print "[!] Error: " + str(GetLastError())
    sys.exit()
    
print "[+] " + disposition_output[Disposition.value]

raw_input("\n[+] Press enter to delete the hidden key? ")
windll.ntdll.NtDeleteKey(HiddenKeyHandle)
windll.ntdll.NtDeleteKey(TargetKeyHandle)

