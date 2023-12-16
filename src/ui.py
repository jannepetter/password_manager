import ttkbootstrap as ttk
import ttkbootstrap.constants as bconst
from ttkbootstrap.tooltip import ToolTip
from tkinter import filedialog
from handle_data import (
    login,
    read_data,
    write_data,
    db_init,
    change_login_password,
    check_if_first_login,
    copy_db_to_location,
    restore_db_from_location,
    DB_NAME,
    validate_password,
    validate_username,
    REQUIRED_PASSWORD_SCORE,
    MIN_MASTER_PASSWORD_LENGTH,
    read_config,
    save_config,
)
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.dialogs import Messagebox
import pyperclip

ERROR_MSG_TIME = 5000


def create_button(text, call_back):
    btn = ttk.Button(
        text=text,
        command=call_back
    )
    return btn


class SubPage(ttk.Frame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.master = master
        self.switch_page_callback = switch_page_callback

    def create_buttonbox(self, submit_btn_name="Submit", cancel_btn_name="Cancel"):
        """Submit and cancel buttons for forms"""
        container = ttk.Frame(self)
        container.pack(pady=15)

        sub_btn = ttk.Button(
            master=container,
            text=submit_btn_name,
            command=self.on_submit,
            bootstyle=bconst.SUCCESS,
            width=6,
        )
        sub_btn.pack(side=bconst.RIGHT, padx=5)
        sub_btn.focus_set()

        cnl_btn = ttk.Button(
            master=container,
            text=cancel_btn_name,
            command=self.on_cancel,
            bootstyle=bconst.DANGER,
            width=6,
        )
        cnl_btn.pack(side=bconst.RIGHT, padx=5)

        return container

    def create_form_entry(self, master, label, variable, type_password=False, width=20, buttons=[], anchor="center"):
        """Create a single form entry"""
        container = ttk.Frame(master)
        container.pack(anchor=anchor, pady=5)

        lbl = ttk.Label(master=container, text=label)
        lbl.pack(anchor="nw", padx=5)

        ent = ttk.Entry(master=container, textvariable=variable, width=width)
        if type_password:
            ent = ttk.Entry(master=container,
                            textvariable=variable, show="*", width=width)

        ent.pack(side=bconst.LEFT, padx=5)
        for el in buttons:
            el.pack(in_=container, side=bconst.LEFT, padx=5)

        return ent

    def on_submit(self):
        pass

    def on_cancel(self):
        pass

    def confirm_choice(self, message, title):
        return Messagebox.yesno(message=message, title=title, parent=self)


class LoginPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        self.first_login = check_if_first_login()
        self.label = ttk.Label(self, text="Login to your password manager!")
        self.label.pack(pady=15)
        self.error_label = ttk.Label(self, text="", foreground="red")
        self.error_label.pack(pady=2)

        self.username = ttk.StringVar(value="")
        self.password = ttk.StringVar(value="")
        self.password_confirm = ttk.StringVar(value="")

        self.create_form_entry(self, "Username", self.username)
        self.create_form_entry(
            self, "Password", self.password, type_password=True)

        if self.first_login:
            self.create_form_entry(
                self, "Confirm password", self.password_confirm, True)
            help_text = f"""
            Select your username and password\n
            Password min lenght {MIN_MASTER_PASSWORD_LENGTH}. Uppercase, lowercase, number and special char required.
            """
            if not self.master.use_validation:
                # remove when finished product
                help_text = "Select your username and password"

            self.label.config(text=help_text)

        self.create_buttonbox()

    def on_error(self, error_msg):
        """Show error and clear entries."""
        self.error_label.config(text=error_msg)
        self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))

    def on_submit(self):
        """Submit the login data."""
        error_msg = None

        if self.first_login and self.password.get() != self.password_confirm.get():
            error_msg = "Your password does not match with the confirm password"

        if error_msg:
            self.on_error(error_msg)
            return

        password_score, password_errors = validate_password(
            self.password.get())
        if self.master.use_validation and self.first_login and password_score < REQUIRED_PASSWORD_SCORE:
            err_msg = "\n".join(err for err in password_errors)
            self.on_error(err_msg)
            return

        username_errors = validate_username(self.username.get())
        if self.master.use_validation and self.first_login and username_errors:
            err_msg = "\n".join(err for err in username_errors)
            self.on_error(err_msg)
            return

        self.master.key = login(
            self.password.get(),
            self.username.get()
        )

        if self.master.key:
            self.master.navigation.set_navbar_status("")
            self.show_data_page()
            return

        error_msg = "Wrong username or password!"
        self.on_error(error_msg)

    def on_cancel(self):
        """Cancel and close the application."""
        self.quit()

    def show_data_page(self):
        self.switch_page_callback(DataPanel)


class PaginationFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.current_page = ttk.IntVar(self, 0)
        x_pad = 2
        y_pad = 2
        label_frame = ttk.Frame(self)
        pag_label = ttk.Label(label_frame, text="Page")
        pag_label.pack(side=bconst.LEFT)
        self.info_label = ttk.Label(label_frame, text="")
        self.info_label.pack(side=bconst.LEFT, padx=10)
        label_frame.pack(anchor="w")
        prev = ttk.Button(
            self,
            text="prev",
            command=lambda: self.paginate(self.current_page.get(), -1)
        )
        prev.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        next = ttk.Button(
            self,
            text="next",
            command=lambda: self.paginate(self.current_page.get(), +1)
        )
        next.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.page_entry = ttk.Entry(
            self, width=3, textvariable=str(self.current_page))
        self.page_entry.pack(side=bconst.LEFT, padx=x_pad)
        go = ttk.Button(
            self,
            text="go",
            command=lambda: self.paginate(self.current_page.get(), 0)
        )
        go.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)

    def paginate(self, page, addition):
        new_page = page + addition
        if new_page < 0:
            self.current_page.set(0)
            return
        self.current_page.set(new_page)
        self.page_entry.config(textvariable=str(self.current_page))

        self.master.data_list, count = read_data(
            self.master.master.key,
            limit=self.master.master.pagination_limit,
            page=new_page,
            search_word=self.master.search_var.get()
        )
        self.total_count = count
        for child in self.master.button_frame.winfo_children():
            child.destroy()
        self.master.create_description_list()
        self.update_info()

    def update_info(self):
        txt = f"{self.current_page.get()} / {self.total_count//self.master.master.pagination_limit}  (Total: {self.total_count})"
        self.info_label.config(text=txt)


class DataPanel(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        self.search_frame = ttk.Frame(self)
        self.search_frame.pack(side=bconst.TOP, fill=bconst.X)
        self.search_var = ttk.StringVar(value="")
        btn = create_button("search", self.search)
        self.create_form_entry(self.search_frame, "Search",
                               self.search_var, anchor="w", buttons=[btn])

        self.common_frame = ttk.Frame(self)
        self.common_frame.pack(side=bconst.TOP, fill=bconst.X)
        self.button_frame = ScrolledFrame(
            self.common_frame, autohide=True, height=400)
        self.button_frame.pack(side=bconst.LEFT, padx=5, fill=bconst.BOTH)

        self.details_frame = ttk.Frame(self.common_frame)
        self.details_frame.pack(side=bconst.LEFT, padx=30)
        anchor = "w"

        self.entry_description_var = ttk.StringVar(value="")
        copy_desc_btn = create_button(
            "copy",
            lambda: self.copy_to_clipboard(self.entry_description_var.get())
        )
        self.create_form_entry(
            self.details_frame,
            "Description",
            self.entry_description_var,
            buttons=[copy_desc_btn],
            anchor=anchor,
        )

        self.entry_username_var = ttk.StringVar(value="")
        copy_uname_btn = create_button(
            "copy",
            lambda: self.copy_to_clipboard(self.entry_username_var.get())
        )
        self.create_form_entry(
            self.details_frame,
            "Username", self.entry_username_var,
            buttons=[copy_uname_btn],
            anchor=anchor,
        )

        self.entry_password_var = ttk.StringVar(value="")
        copy_passw_btn = create_button(
            "copy",
            lambda: self.copy_to_clipboard(self.entry_password_var.get())
        )
        toggle_show_passw_btn = create_button(
            "show",
            lambda: self.toggle_show_entry_password()
        )
        self.password_entry = self.create_form_entry(
            self.details_frame,
            "Password",
            self.entry_password_var,
            type_password=True,
            buttons=[
                copy_passw_btn,
                toggle_show_passw_btn
            ],
            anchor=anchor,
        )
        self.paginator = PaginationFrame(self)
        self.paginator.pack(anchor="w")
        self.data_list, count = read_data(
            self.master.key,
            limit=self.master.pagination_limit,
        )
        self.paginator.total_count = count
        self.create_description_list()
        self.paginator.update_info()

    def create_description_list(self):
        for i, data in enumerate(self.data_list):
            button = ttk.Button(
                self.button_frame,
                text=data["description"],
                command=lambda idx=i: self.show_details(idx),
                bootstyle=bconst.SECONDARY,
                width=25,
            )
            button.grid(row=i, column=0, sticky="ew", pady=2)

    def show_details(self, index):
        detail = self.data_list[index]
        description = detail["description"]
        username = detail["username"]
        password = detail["password"]
        self.entry_description_var.set(description)
        self.entry_username_var.set(username)
        self.entry_password_var.set(password)

    def copy_to_clipboard(self, variable):
        pyperclip.copy(variable)

    def toggle_show_entry_password(self):
        current_show_state = self.password_entry.cget("show")
        new_show_state = "" if current_show_state == "*" else "*"
        self.password_entry.config(show=new_show_state)

    def search(self):
        for child in self.button_frame.winfo_children():
            child.destroy()

        self.paginator.current_page.set(0)
        if self.search_var.get() == "":
            self.data_list, count = read_data(
                self.master.key,
                limit=self.master.pagination_limit,
                page=self.paginator.current_page.get(),
            )
        else:
            self.data_list, count = read_data(
                self.master.key,
                limit=self.master.pagination_limit,
                search_word=self.search_var.get(),
                page=self.paginator.current_page.get(),
            )

        self.paginator.total_count = count
        self.create_description_list()
        self.paginator.update_info()


class Navigation(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        style_str = "nav_button.Link.TButton"
        self.status = ttk.StringVar(value=bconst.DISABLED)

        x_pad = 5
        y_pad = 5
        self.nav_buttons = []
        data_button = ttk.Button(
            self.master,
            text="Data",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(DataPanel),
            style=style_str,
        )
        data_button.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(data_button)

        add_button = ttk.Button(
            self.master,
            text="Add",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(AddDataPage),
            style=style_str,
        )
        add_button.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(add_button)

        options_button = ttk.Button(
            self.master,
            text="Options",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(OptionsPage),
            style=style_str,
        )
        options_button.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(options_button)

        password_change_btn = ttk.Button(
            self.master,
            text="Change password",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(
                ChangeMasterPasswordPage),
            style=style_str,
        )
        password_change_btn.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(password_change_btn)

        backup_btn = ttk.Button(
            self.master,
            text="Backups",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(BackupDataPage),
            style=style_str,
        )
        backup_btn.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(backup_btn)

        logout_button = ttk.Button(
            self.master,
            text="Logout",
            state=self.status.get(),
            style=style_str,
        )
        logout_button.pack(side=bconst.RIGHT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(logout_button)

    def set_navbar_status(self, status):
        for el in self.nav_buttons:
            el.config(state=status)


class AddDataPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        self.label = ttk.Label(self, text="Create a new data entry")
        self.label.pack(pady=10)

        self.description = ttk.StringVar(value="")
        self.username = ttk.StringVar(value="")
        self.password = ttk.StringVar(value="")

        self.create_form_entry(self, "Description", self.description)
        self.create_form_entry(self, "Username", self.username)
        self.create_form_entry(
            self, "Password", self.password, type_password=True)
        self.create_buttonbox()

    def on_submit(self):
        # TODO: add checks to see that data is valid
        write_data(
            self.master.key,
            self.description.get(),
            self.password.get(),
            self.username.get()
        )

        self.description.set("")
        self.password.set("")
        self.username.set("")

        self.label.config(text="New entry added successfully. Add another?")

    def on_cancel(self):
        self.switch_page_callback(DataPanel)


class ChangeMasterPasswordPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        text = f"""
        Change master password and/or username\n
        Min length {MIN_MASTER_PASSWORD_LENGTH} chars. Upper, lower, number and special char required.
        """
        # switch for developing, remove when finished product
        if not self.master.use_validation:
            # remove when finished product
            text = "Change master password and/or username"

        self.label = ttk.Label(self, text=text)
        self.label.pack()

        self.error_label = ttk.Label(self, text="", foreground="red")
        self.error_label.pack()

        form_frame = ttk.Frame(self)
        form_frame.pack(side=bconst.TOP)
        old_frame = ttk.Frame(form_frame)
        old_frame.pack(side=bconst.LEFT, fill=bconst.BOTH, padx=50, pady=10)
        new_frame = ttk.Frame(form_frame)
        new_frame.pack(side=bconst.LEFT, fill=bconst.BOTH, padx=15, pady=10)

        self.old_username = ttk.StringVar(value="")
        self.old_password = ttk.StringVar(value="")

        self.create_form_entry(old_frame, "Old Username", self.old_username)
        self.create_form_entry(old_frame, "Old Password",
                               self.old_password, type_password=True, anchor="nw")

        self.new_username = ttk.StringVar(value="")
        self.new_password = ttk.StringVar(value="")
        self.confirm_new_password = ttk.StringVar(value="")

        self.create_form_entry(new_frame, "New Username", self.new_username)
        self.create_form_entry(new_frame, "New Password",
                               self.new_password, type_password=True)
        self.create_form_entry(new_frame, "Confirm New Password",
                               self.confirm_new_password, type_password=True)

        self.create_buttonbox()

    def on_submit(self):

        new_username = self.new_username.get()
        new_password = self.new_password.get()
        confirm_new_password = self.confirm_new_password.get()

        # Check before popping the confirm screen
        if new_password != confirm_new_password:
            self.on_error(
                "New password does not match the Confirm New password field!")
            return

        # Check validations before popping the confirm screen
        score, password_errors = validate_password(new_password)
        if self.master.use_validation and score < REQUIRED_PASSWORD_SCORE:
            password_err_msg = "\n".join(err for err in password_errors)
            self.on_error(password_err_msg)
            return

        # Check validations before popping the confirm screen
        username_errors = validate_username(new_username)
        if self.master.use_validation and username_errors:
            username_err_msg = "\n".join(err for err in username_errors)
            self.on_error(username_err_msg)
            return

        choice = self.confirm_choice(
            "Confirm Master Password & Username change", "Change Master Password & Username")

        if choice != "Yes":
            return

        old_username = self.old_username.get()
        old_password = self.old_password.get()

        success, new_key, login_error = change_login_password(
            old_username,
            old_password,
            new_username,
            new_password,
        )

        if success:
            self.master.key = new_key
            self.label.config(
                text="New Username and Password set successfully!")
            self.old_password.set("")
            self.old_username.set("")
            self.new_username.set("")
            self.new_password.set("")
            self.confirm_new_password.set("")

        if login_error:
            self.on_error(login_error)

    def on_cancel(self):
        self.switch_page_callback(DataPanel)

    def on_error(self, message):
        self.error_label.config(text=message)
        self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))


class BackupDataPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        page_frame = ttk.Frame(self, height=40, width=20)
        page_frame.pack(side=bconst.RIGHT, pady=10, padx=10)
        self.default_label_txt = "Create or restore a backup from your database."
        self.label = ttk.Label(page_frame, text=self.default_label_txt)
        self.label.pack(anchor="w")
        self.error_label = ttk.Label(page_frame, text="", foreground="red")
        self.error_label.pack(anchor="w")

        btn = ttk.Button(
            page_frame,
            text="Copy your database to location",
            command=self.backup_database,
        )
        tooltip_backup = f"""
        Select a location and specify the name for the saved database, then click Save.
        The database will be copied to your selected location. The same result can achieved by simply
        copying your {DB_NAME} to your desired location
        """.replace("\n", "")
        ToolTip(btn, text=tooltip_backup)
        btn.pack(anchor="w", pady=25)

        self.restore_label = ttk.Label(
            page_frame, text="Restore your database from location. Warning this will overwrite the current database!")
        self.restore_label.pack(anchor="w")
        self.restore_label2 = ttk.Label(
            page_frame, text="Remember that login to old database requires the old database password and username")
        self.restore_label2.pack(anchor="w")

        restore_btn = ttk.Button(
            page_frame,
            text="Restore database from location",
            command=self.restore_database,
            bootstyle="danger"
        )
        tooltip_restore = f"""
        Select a backup file to be restored as application database. The file will be copied from your
        selected location to the project root. The same result can also be achieved by simply copying
        your backup database and pasting it to the project root with name as {DB_NAME}
        """.replace("\n", "")
        ToolTip(restore_btn, text=tooltip_restore)
        restore_btn.pack(anchor="w", pady=15)

    def backup_database(self):
        file_path = filedialog.asksaveasfilename(
            title="Copy database to location")

        if isinstance(file_path, str) and file_path != "":
            success, error = copy_db_to_location(file_path)
            if success:
                self.label.config(text="Database copied successfully!")
                self.after(5000, lambda: self.label.config(
                    text=self.default_label_txt))
            elif error:
                self.on_error(error)

    def restore_database(self):
        file_path = filedialog.askopenfile(
            title="Restore database from location", filetypes=(("All files", "*.db"),))
        if file_path == None:
            return

        choise = self.confirm_choice(
            "Current database will be overwritten! Are you sure you want to restore your old database?", "Confirm database restore")
        if choise != "Yes":
            return

        file_name = ""
        if hasattr(file_path, "name"):
            file_name = file_path.name

        if isinstance(file_name, str) and file_name != "":
            success, error = restore_db_from_location(file_name)
            if success:
                # TODO: replace with logout function when that is ready
                self.master.key = None
                self.switch_page_callback(LoginPage)
            elif error:
                self.on_error(error)
        else:
            self.on_error("Error occurred, database was not restored!")

    def on_error(self, message):
        self.error_label.config(text=message)
        self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))


class OptionsPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        self.config = read_config()
        self.label = ttk.Label(self, text="Options", font=("Helvetica", 12))
        self.label.pack()

        options_frame = ttk.Frame(self)
        options_frame.pack(side=bconst.TOP, fill=bconst.X)
        left_options = ttk.Frame(options_frame)
        left_options.pack(side=bconst.LEFT, padx=30, pady=10, fill=bconst.Y)

        # Theme
        self.theme_var = ttk.IntVar(
            self, 0 if self.master._style.theme.name == "darkly" else 1)
        self.theme_btn = ttk.Checkbutton(
            left_options,
            text="dark/light theme",
            bootstyle="success-round-toggle",
            command=self.toggle_theme,
            variable=self.theme_var
        )
        self.theme_btn.pack(anchor="w", pady=20)

        # Autologout time
        self.logout_time = ttk.IntVar(self, self.config.get("logout", 10))
        logout_choices = [-1, 10, 15]
        logout_label = ttk.Label(left_options, text="Select logout time (min)")
        logout_label.pack(anchor="w", pady=10)
        for choice in logout_choices:
            text_val = "Never" if choice == -1 else str(choice) + " min"
            ttk.Radiobutton(
                left_options,
                text=text_val,
                variable=self.logout_time,
                value=choice,
                command=self.select_logout_time,
            ).pack(anchor="w", padx=10)

        # Pagination
        self.pagination_amount = ttk.IntVar(
            self, self.config.get("pagination", 200))
        pagination_label = ttk.Label(
            left_options, text="How many passwords per page")
        pagination_label.pack(pady=10)
        pagination_options = [100, 200, 500]
        for choice in pagination_options:
            ttk.Radiobutton(
                left_options,
                text=str(choice),
                variable=self.pagination_amount,
                value=choice,
                command=self.select_pagination,
            ).pack(anchor="w", padx=10)

        # Random password length
        self.min_password_length = 1
        self.max_password_length = 128
        self.random_password_length = ttk.IntVar(
            self, self.config.get("random_password_length", 30))
        self.random_password_length.trace_add(
            "write", self.set_random_password_length)
        password_label = ttk.Label(
            left_options, text="Generated password length")
        password_label.pack(anchor="w", pady=10)
        box = ttk.Spinbox(
            left_options,
            width=5,
            command=self.set_random_password_length,
            from_=self.min_password_length,
            to=self.max_password_length,
            textvariable=self.random_password_length,
        )
        box.pack(anchor="w")
        btn_box = self.create_buttonbox(submit_btn_name="Save")
        btn_box.pack(pady=50, side="top")

    def toggle_theme(self):
        current = self.master._style.theme.name
        if current == "darkly":
            self.master._style.theme_use("cosmo")
        else:
            self.master._style.theme_use("darkly")

        self.master.activate_custom_styles()

    def select_logout_time(self):
        print('select log time', self.logout_time.get())

        # TODO: connect to autologout feature

    def select_pagination(self):
        print('select pagination', self.pagination_amount.get())
        self.master.pagination_limit = self.pagination_amount.get()

    def set_random_password_length(self, *args):
        length = self.random_password_length.get()
        if length > self.max_password_length:
            self.random_password_length.set(self.max_password_length)

        if length < self.min_password_length:
            self.random_password_length.set(self.min_password_length)

        # TODO: connect to autogenerate password feature

    def on_submit(self):
        logout = self.logout_time.get()
        pagination = self.pagination_amount.get()
        random_password_length = self.random_password_length.get()
        ui_theme = self.master._style.theme.name
        save_config({
            "logout": logout,
            "pagination": pagination,
            "random_password_length": random_password_length,
            "ui_theme": ui_theme,
        })
        self.master.app_config = read_config()

    def on_cancel(self):
        """
        Return the config settings.
        """
        config_theme = self.config.get("ui_theme", "darkly")
        self.theme_var.set(0 if config_theme == "darkly" else 1)
        self.master._style.theme_use(config_theme)
        self.master.activate_custom_styles()
        self.logout_time.set(self.config.get("logout", 10))
        self.master.pagination_limit = self.config.get("pagination", 200)
        self.pagination_amount.set(self.config.get("pagination", 200))
        self.random_password_length.set(
            self.config.get("random_password_length", 30))


class MainApplication(ttk.Window):
    def __init__(self, app_config):
        # switch for development to bypass validation. Remove when product finished
        self.use_validation = False
        self.app_config = app_config
        self.pagination_limit = app_config.get("pagination", 200)
        theme = app_config.get("ui_theme", "darkly")
        super().__init__(themename=theme)
        db_init()
        self.activate_custom_styles()
        self.title("Password manager")
        self.geometry("800x600+100+100")

        self.navigation_frame = ttk.Frame(self)
        self.navigation_frame.pack(side=bconst.TOP)

        self.page_frame = ttk.Frame(self)
        self.page_frame.pack(side=bconst.BOTTOM, fill="both", expand=True)

        self.navigation = Navigation(self, self.switch_page)
        self.navigation.pack(in_=self.navigation_frame)

        self.current_page = None
        self.show_page(LoginPage)

    def show_page(self, page_class):
        new_page = page_class(self, self.switch_page)

        if self.current_page is not None:
            self.current_page.destroy()

        new_page.pack(in_=self.page_frame, fill="both", expand=True)
        self.current_page = new_page

    def switch_page(self, page_class):
        self.show_page(page_class)

    def on_close(self):
        self.destroy()

    def activate_custom_styles(self):
        self._style.configure("nav_button.Link.TButton",
                              font=("Helvetica", 12))
