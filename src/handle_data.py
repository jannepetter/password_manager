from sqlite3 import connect
import secrets
from string import ascii_letters, digits, punctuation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import os
import base64
import json
import shutil
from pathlib import Path

DB_NAME = "manager.db"
ENCODING = "utf-8"
VECTOR_LENGTH = 16
KEY_ITERATIONS = 5000000
CONFIG_PATH = "config.json"
DEFAULT_CONFIG = {
    "logout":15,
    "ui_theme":"darkly"
}


def generate_key(password:str, username:str):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=KEY_ITERATIONS,
        salt=username.encode(),
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    return key

def _encrypt(plaintext:str, key, init_vector):
    """
    Encrypt with aes256.

    Padding is also provided, incase the data is smaller than the block size.
    """
    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext.encode(ENCODING)) + padder.finalize()
    cipher = Cipher(algorithms.AES256(key), modes.CFB(init_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_bytes = encryptor.update(padded_plaintext) + encryptor.finalize()
    ciphertext = base64.b64encode(cipher_bytes).decode(ENCODING)

    return ciphertext

def _decrypt(ciphertext, key, init_vector):
    """
    Removes the encryption and the padding. Returns the plaintext
    """
    decoded_cipher = base64.b64decode(ciphertext)
    cipher = Cipher(algorithms.AES256(key), modes.CFB(init_vector), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_text = decryptor.update(decoded_cipher) + decryptor.finalize()

    unpadder = padding.PKCS7(256).unpadder()
    # Unpad the decrypted text
    decrypted_bytes = unpadder.update(decrypted_padded_text) + unpadder.finalize()
    decrypted_text = decrypted_bytes.decode(ENCODING)
    return decrypted_text

def generate_random_password(length):
    """
    Generates random password.
    """
    characters = ascii_letters + digits + punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    return password

def _decrypt_raw_data(key, rows):
    data = []
    for row in rows:
        id = row[0]
        init_vector = row[4]
        description = _decrypt(row[1],key,init_vector)
        password = _decrypt(row[2],key,init_vector)
        username = _decrypt(row[3],key,init_vector)

        data.append(
            {
                "id":id,
                "description":description,
                "password":password,
                "username":username
            }
        )
    
    return data

def read_data(key):
    """
    Reads data from db and returns a list of dicts containing user data in decrypted form.
    [
        {
        "id":id,
        "description":description,
        "password":password,
        "username":username
        }
    ]
    """
    ok = check_master_password_ok(key)

    if not ok:
        # return empty list if the key (username & password) are wrong
        return []
    
    conn = connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, description, password, username, vector
        FROM passwords
    ''')

    rows = cursor.fetchall()
    data = _decrypt_raw_data(key,rows)
        
    conn.close()

    return data

def check_master_password_ok(key):
    """
    Protects the db and the user from writing data with wrong password to the db.

    Decrypting with wrong password will raise an error and it is important that 
    all the data is encrypted with the same master password.
    """
    conn = connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT description, vector
        FROM passwords
    ''')
    rows = cursor.fetchall()
    try:
        for row in rows:
            init_vector = row[1]
            _decrypt(row[0],key,init_vector)
    except Exception:
        conn.close()
        return False
    
    conn.close()
    return True


def write_data(key,description,password,username="")-> bool:
    """
    Writes a new entry to db. Returns True if successful
    """
    ok = check_master_password_ok(key)

    if not ok:
        # return if the key (username & password) are wrong
        return False
    
    init_vector = os.urandom(VECTOR_LENGTH)
    encrypted_description = _encrypt(description,key,init_vector)
    encrypted_password = _encrypt(password,key,init_vector)
    encrypted_username = _encrypt(username,key,init_vector)

    conn = connect(DB_NAME)
    cursor = conn.cursor()

    # Insert data into the table
    cursor.execute('''
        INSERT INTO passwords (description, password, username, vector)
        VALUES (?, ?, ?, ?)
    ''', (encrypted_description, 
        encrypted_password, 
        encrypted_username,
        init_vector
        ))
    conn.commit()
    conn.close()

    return True


def delete_data(key,id)-> bool:
    """
    Deletes the entry by id.
    """
    ok = check_master_password_ok(key)
    if not ok:
        # return if the key (username & password) are wrong
        return False
    
    conn = connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(f"DELETE FROM passwords WHERE id = ?", (id,))
    conn.commit()

    conn.close()

def edit_data(key,id,description,password,username):
    """
    Edits the stored entry
    """
    ok = check_master_password_ok(key)
    if not ok:
        # return if the key (username & password) are wrong
        return False

    init_vector = os.urandom(VECTOR_LENGTH)
    encrypted_description = _encrypt(description,key,init_vector)
    encrypted_password = _encrypt(password,key,init_vector)
    encrypted_username = _encrypt(username,key,init_vector)


    conn = connect(DB_NAME)
    cursor = conn.cursor()

    # Insert data into the table
    cursor.execute('''
        UPDATE passwords SET description = ?, password = ?, username = ?, vector = ?
        WHERE id = ?
    ''', (encrypted_description, 
          encrypted_password, 
          encrypted_username,
          init_vector,
          id
          ))
    conn.commit()
    conn.close()

def change_login_password(username, password, new_username, new_password):
    """
    Changes the password that user uses for encrypting and decrypting. The master password.

    Errors happening in the middle of the process will lead to rollback. The success of the
    encryption is also tested with each entry that it matches the original data. Incase it 
    does not, the change of the master password is aborted and rollback occurs.
    """
    error = ""
    key = generate_key(password,username)

    ok = check_master_password_ok(key)
    if not ok:
        error = "Old username and password did not match!"
        return False,None, error
    
    original_data = read_data(key)
    try:
        new_key = generate_key(new_password,new_username)

        conn = connect(DB_NAME)
        conn.execute('BEGIN TRANSACTION')
        cursor = conn.cursor()

        for el in original_data:

            init_vector = os.urandom(VECTOR_LENGTH)
            id = el["id"]
            description = el["description"]
            password = el["password"]
            username = el["username"]

            encrypted_description = _encrypt(description,new_key,init_vector)
            encrypted_password = _encrypt(password,new_key,init_vector)
            encrypted_username = _encrypt(username,new_key,init_vector)

            cursor.execute('''
                UPDATE passwords SET description = ?, password = ?, username = ?, vector = ?
                WHERE id = ?
            ''', (encrypted_description, 
                encrypted_password, 
                encrypted_username,
                init_vector,
                id
                ))
        
        # Data should be identical to original data when decrypted. Raise error if not.
        
        cursor.execute('''
            SELECT id, description, password, username, vector
            FROM passwords
        ''')

        rows = cursor.fetchall()
        data = _decrypt_raw_data(new_key,rows)

        # check that each entry matches the old when decrypted with the new key
        for i in range(len(original_data)):
            assert original_data[i]["id"] == data[i]["id"], "id is not the same"
            assert original_data[i]["description"] == data[i]["description"], "description is not the same"
            assert original_data[i]["password"] == data[i]["password"], "password is not the same"
            assert original_data[i]["username"] == data[i]["username"], "username is not the same"

        conn.commit()
        
    except Exception as e:
        error = "Password change failed!"
        conn.rollback()
        conn.close()
        return False, None, error
        
    conn.close()
    return True,new_key, error

    

def login(password,username):
    """
    Returns a key for db actions. 
    
    Returns None if the provided username and password are wrong
    """
    key = generate_key(password, username)
    ok = check_master_password_ok(key)

    if ok:
        return key
    
    return None


def copy_db_to_location(location_to_save):
    """
    For taking backups from the db. Saves it to user defined location.
    """
    try:
        path = Path()
        db_path = path.resolve() / DB_NAME
        if ".db" not in location_to_save:
            location_to_save= location_to_save+".db"
        shutil.copy(db_path,location_to_save)
    except Exception as e:
        return False, e
    
    return True, None

def restore_db_from_location(location_to_restore):
    """
    Restore database from location.
    """
    try:
        path = Path()
        db_path = path.resolve() / DB_NAME
        shutil.copy(location_to_restore,db_path)
    except Exception as e:
        return False, e
    
    return True, None



def db_init():
    """
    Inits the db if it does not yet exist. E.g user starts the app for the first time.
    """
    conn = connect(DB_NAME)
    cursor = conn.cursor()
    CREATE_TABLE_QUERY = '''
        CREATE TABLE IF NOT EXISTS passwords(
            id INTEGER PRIMARY KEY,
            description TEXT,
            password TEXT,
            username TEXT,
            vector BLOB
        )
    '''
    cursor.execute(CREATE_TABLE_QUERY)
    conn.commit()
    conn.close()

def read_config():
    """
    Read application configs.
    """
    data = None

    try:
        with open(CONFIG_PATH, "r") as json_file:
                
                data = json.load(json_file)

                if not isinstance(data,dict):
                    raise ValueError("Config data was not a dict")
                
    except Exception:
            # config.json is not found, damaged, etc.
            data = DEFAULT_CONFIG

    return data

def save_config(data):
    """
    Save configs.
    """
    error = None
    try:
        if not isinstance(data,dict):
            raise ValueError("Config data must be a dict. Restoring default config")
        
        if "ui_theme" not in data:
            raise ValueError("Config data must contain ui_theme. Restoring default config")
        
        if "logout" not in data:
            raise ValueError("Config data must contain logout time. Restoring default config")
        
        with open(CONFIG_PATH, "w") as json_file:
            json.dump(data, json_file, indent=4)
            return error

    except Exception as e:
        error = e
        # something went wrong, save default config to recover.
        with open(CONFIG_PATH, "w") as json_file:
            json.dump(DEFAULT_CONFIG, json_file, indent=4)
    
    return error

def check_if_first_login():
    conn = connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT vector
        FROM passwords
    ''')
    rows = cursor.fetchall()
    
    conn.close()
    return len(rows) == 0
            




