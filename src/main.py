from ui import UI


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
    print("password manager app")
    ui = UI()

if __name__ == "__main__":
    main()