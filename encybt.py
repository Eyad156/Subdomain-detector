import bcrypt

# The password you want to hash
password = b"$2a$10$DhX6yWgs3wlnRYssYhqeR.GyM8.7zwFER6AjdGHIfHjxCKKI2N56e"

# Generate a salt
salt = bcrypt.gensalt()

# Hash the password
hashed_password = bcrypt.hashpw(password, salt)

print(hashed_password)