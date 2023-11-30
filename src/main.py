from ui import UI
from handle_data import db_init, write_data, read_data, login


def main():
    """
    handle_data file handles the db interactions.
    The functions in handle_data are used in the UI and imported there from handle_data.py
    UI is imported in the main.py

    This should avoid circular import issues

    Assuming we are using virtual environment named venv, which is now gitignored along with __pycache__.
    Use your virtual environment of choice. If you name the environment differently, just gitignore it too

    I have named the requirements file as requirements.txt
    """
    password = "example_pass"
    username = "example_user"

    # example use of the db. Remove when finished.
    db_init()
    key = login(password,username)
    data = {
        "description":"test description",
        "password":"some_password",
        "username":"some_username"
    }
    ok = write_data(key, **data)
    print("write data ok: ", ok)

    data = read_data(key)
    print('Reading data:')
    for el in data:
        print(el)

if __name__ == "__main__":
    main()