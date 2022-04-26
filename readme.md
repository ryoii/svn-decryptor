# Svn-Decrypter

Decrypt the user's password saved by svn in windows. Reminds you of forgotten password.

### How it works

Subversion saved you password with an encrypted string. The encrypt/decrypt algorithm is provided by win api.

> This function decrypts and checks the integrity of the data in a BLOB (Cryptography) structure. Usually, only a user with the same logon credentials as the encrypter can decrypt the data. In addition, the encryption and decryption must be done on the same computer.

### Usage

Download on the release page and just run it.

### Reference

[TortoiseSVN Password Decrypter](http://www.leapbeyond.com/ric/TSvnPD/): Must have the Microsoft .NET 2.0 runtime.