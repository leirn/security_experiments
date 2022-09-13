# How to securely store password ?

- Use adapted hash algorythm, such as bcrypt
- Use salting (already embedded in bcrypt format) and peppering

The recommended approach is:
hashed_pwd = bcrypt(hmac_512(password, pepper))
