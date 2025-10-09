when setting up:

1. activate venv
2. Run `pip install -r requirements.txt`

You will need a .env file with the following keys and values:

1. "AWS_ACCESS_KEY_ID": your aws access key
2. "AWS_SECRET_ACCESS_KEY": your aws secret key
3. "PEPPER": any value of you choosing
4. "SESSION_COOKIE_SECRET_KEY": any value of your choosing

You may also need the following environment variable set

1. "DATABASE_URL": the postgres database path to your database. Leave blank if using a local sqlite database
2. "INITIAL_ADMINS": a list of admins with a username, password, and second password in json form.

example for INITIAL_ADMINS:\
INITIAL_ADMINS='[\
  {"username": "admin", "pass1": "SomeStrongP@ss!", "pass2": "required"},
  {"username": "dev_admin", "pass1": "devpassword123", "pass2": "secondfactor"}\
]'
