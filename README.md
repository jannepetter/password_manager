# password manager

## Ui
A quick cookup with tkinter and tkinterbootstrap for UI demo. 
Login is bypassed and only static data is currently shown.

## Database
Done using sqlite. Uses AES 256 encryption and the data is always stored in there as encrypted.
During the reading process the data is decrypted back to readable form with a key generated
by the users chosen password and username. If user forgets the password, they cannot recover the
data, same thing if they cannot remember the username. Everything except the entry id is
encrypted in the tables. The database can only have one user.

The key generation is made computationally expensive to prevent brute forcing. The required 
iterations being 5000000 iterations for key generation. It takes an average computer around
2.5 seconds to create a single key. When this is combined to a strong password, it should be
enough to prevent brute forcing attempts.

The user data is being protected with the AES 256 encryption, but also with random initializing
vector, so that the same plain text will produce each time a different cipher text. Also a padding
is used to mask the length of the data. The adversary should not be able find out the true length
of the values stored in the database becouse of this, if they get their hands on the database
and investigate the ciphered values.

For further instructions how to use, please check the /tests folder
```
# You can also run the tests
python3 -m unittest discover -s tests
