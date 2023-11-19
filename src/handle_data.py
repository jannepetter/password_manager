

def read_data():
    """
    Reads data from db and returns a list of user stored passwords with their ids.
    Could be a list of tuples [(id,description,password)] or something else.
    """
    pass

def write_data(description, password):
    """
    Writes a new password to db.
    """
    pass

def delete_data(id):
    """
    Deletes the stored password from database
    """
    pass

def edit_data():
    """
    Edits the stored password
    """
    pass

def change_login_password():
    """
    Changes the password that user uses for login.
    """
    pass

def login():
    """
    Makes db readable

    This might have to be done in the ui. Depending on the solution we choose for storing data
    """
    pass

def logout():
    """
    Makes db unreadable

    This might have to be done in the ui
    """
    pass

def copy_db_to_location(location_to_save):
    """
    For taking backups from the db. Saves it to user defined location.
    """
    pass

def check_db_exists()->bool:
    """
    Function to check if db exists. The ui will at startup check if the 
    db exists. If not, then it will query users username and login password.
    After this it will execute db_init()
    """
    pass

def db_init(username, login_password):
    """
    Inits the db if it does not yet exist. E.g user starts the app for the first time.
    """
    pass