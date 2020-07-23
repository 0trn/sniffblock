import os
with open("./database/secrets/auth_salt","w") as f:
	f.write("AUTH_KEY:"+input("Enter a secret salt key for authentification security: "))
with open("./database/secrets/salt","w") as f:
	f.write("SALT_KEY:"+input("Enter a secret salt key for general encryption: "))
os.system("pip install -r requirements.txt -vvv --no-cache-dir")