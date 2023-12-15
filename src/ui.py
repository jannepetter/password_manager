import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttk
import ttkbootstrap.constants as bconst
from handle_data import (
    login,
    read_data,
    write_data,
    db_init,
    change_login_password,
    check_if_first_login,
    delete_data,
    edit_data
)
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.dialogs import Messagebox
import pyperclip

ERROR_MSG_TIME = 3000


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

    def create_buttonbox(self):
        """Submit and cancel buttons for forms"""
        container = ttk.Frame(self)
        container.pack(expand=bconst.YES, pady=(15, 10))

        sub_btn = ttk.Button(
            master=container,
            text="Submit",
            command=self.on_submit,
            bootstyle=bconst.SUCCESS,
            width=6,
        )
        sub_btn.pack(side=bconst.RIGHT, padx=5)
        sub_btn.focus_set()

        cnl_btn = ttk.Button(
            master=container,
            text="Cancel",
            command=self.on_cancel,
            bootstyle=bconst.DANGER,
            width=6,
        )
        cnl_btn.pack(side=bconst.RIGHT, padx=5)

    def create_form_entry(self, master, label, variable, type_password=False, width=20, buttons=[], anchor="center"):
        """Create a single form entry"""
        container = ttk.Frame(master)
        container.pack(anchor=anchor, pady=5)

        lbl = ttk.Label(master=container, text=label)
        lbl.pack(anchor="nw", padx=5)

        ent = ttk.Entry(master=container, textvariable=variable, width=width)
        if type_password:
            ent = ttk.Entry(master=container, textvariable=variable, show="*", width=width)

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
        self.create_form_entry(self, "Password", self.password, type_password=True)

        if self.first_login:
            self.create_form_entry(self, "Confirm password", self.password_confirm, True)
            self.label.config(text="Select your username and password")

        self.create_buttonbox()

    def on_error(self, error_msg):
        """Show error and clear entries."""
        self.error_label.config(text=error_msg)
        self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))
        self.username.set("")
        self.password.set("")
        self.password_confirm.set("")

    def on_submit(self):
        """Submit the login data."""
        error_msg = None

        # TODO: validate username and password on first login
        # required length and complexity for password at least

        if self.first_login and self.password.get() != self.password_confirm.get():
            error_msg = "Your password does not match with the confirm password"

        if error_msg:
            self.on_error(error_msg)
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


class UpdateWindow(tk.Toplevel):
    def __init__(self, master, entry_id):
        self.entry_id = entry_id
        super().__init__(master)
        self.title("Update Password")
        self.geometry("400x400")
        print(self.entry_id)

        # Frame to hold labels, entry widgets, and buttons
        frame = ttk.Frame(self)
        frame.pack(pady=10)

        # Labels and entry widgets
        labels = ["Description", "Username", "New Password:"]
        self.entries = []

        for label_text in labels:
            label = ttk.Label(frame, text=label_text)
            label.grid(row=labels.index(label_text), column=0, padx=5, pady=5)

            if "Password" in label_text:
                entry = PlaceholderEntry(frame, show="*")
                show_button = ttk.Button(frame, text="Show", command=lambda e=entry: self.toggle_show_entry_password(e))
                show_button.grid(row=labels.index(label_text), column=2, padx=5, pady=5)
            else:
                entry = PlaceholderEntry(frame)

            if "Description" in label_text or "Username" in label_text:
                entry.set_placeholder(f"blank if no change {label_text.lower()}")

            entry.grid(row=labels.index(label_text), column=1, padx=5, pady=5)
            self.entries.append(entry)

        # Submit button
        submit_button = ttk.Button(frame, text="Submit", command=self.on_submit)
        submit_button.grid(row=len(labels), column=0, columnspan=2, padx=5, pady=10)

        # Cancel button
        cancel_button = ttk.Button(frame, text="Cancel", command=self.destroy)
        cancel_button.grid(row=len(labels), column=1, columnspan=2, padx=5, pady=10)

    def toggle_show_entry_password(self, entry):
        current_show_state = entry.cget("show")
        new_show_state = "" if current_show_state == "*" else "*"
        entry.config(show=new_show_state)

    def on_submit(self):
        data = []
        for entry in self.entries:
            data.append(entry.get())

        edit_data(
            self.master.key,
            self.entry_id,
            data[0],
            data[1],
            data[2]
        )
        self.destroy()


# Custom Entry widget with placeholder
class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.placeholder = ""

        self.bind("<FocusIn>", self.on_focus_in)
        self.bind("<FocusOut>", self.on_focus_out)
        self.on_focus_out(None)

    def set_placeholder(self, text):
        self.placeholder = text
        self.insert(0, self.placeholder)
        self.configure(foreground="grey")

    def on_focus_in(self, event):
        if self.get() == self.placeholder:
            self.delete(0, "end")
            self.configure(foreground="black")

    def on_focus_out(self, event):
        if not self.get():
            self.insert(0, self.placeholder)
            self.configure(foreground="grey")

    def toggle_show_entry_password(self, index):
        current_show_state = self.entries[index].cget("show")
        new_show_state = "" if current_show_state == "*" else "*"
        self.entries[index].config(show=new_show_state)

    def on_submit(self):
        # TODO: Add logic to handle password update
        pass

    def on_cancel(self):
        self.destroy()


class DataPanel(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        self.current_index = -1
        self.search_frame = ttk.Frame(self)
        self.search_frame.pack(side=bconst.TOP, fill=bconst.X)
        self.search_var = ttk.StringVar(value="")
        btn = create_button("search", self.search)
        self.create_form_entry(self.search_frame, "Search", self.search_var, anchor="w", buttons=[btn])

        self.common_frame = ttk.Frame(self)
        self.common_frame.pack(side=bconst.TOP, fill=bconst.X)
        self.button_frame = ScrolledFrame(self.common_frame, autohide=True)
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
        toggle_update_passw_btn = create_button(
            "update",
            lambda: self.toggle_update_entry_password()
        )

        toggle_delete_passw_btn = create_button(
            "Delete",
            lambda: self.toggle_delete_entry_password(self.current_index)
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
        # Add the 'Delete' button to the next column
        delete_button_frame = ttk.Frame(self.details_frame)
        delete_button_frame.pack(side=bconst.LEFT, padx=5)

        toggle_delete_passw_btn.pack(in_=delete_button_frame, side=bconst.LEFT, padx=5)

        # Add the 'Update' button to the next column
        update_button_frame = ttk.Frame(self.details_frame)
        update_button_frame.pack(side=bconst.LEFT, padx=5)

        toggle_update_passw_btn.pack(in_=update_button_frame, side=bconst.LEFT, padx=5)

        self.data_list = read_data(self.master.key)
        self.create_description_list()

    def toggle_update_entry_password(self):
        entry_id = self.data_list[self.current_index].get('id')
        update_window = UpdateWindow(self.master, entry_id)
        update_window.grab_set()
        update_window.wait_window()
        self.data_list = []
        for child in self.button_frame.winfo_children():
            child.destroy()
        self.data_list = read_data(self.master.key)
        self.create_description_list()
        self.current_index = -1

    def toggle_delete_entry_password(self, index):
        choice = self.confirm_choice(
            message="Confirm Deleting your Entry",
            title="Confirm Deletion"
        )

        if choice == "Yes":
            if index != -1:
                entry_id = self.data_list[index].get('id')
                delete_data(self.master.key, entry_id)
                self.data_list = []
                for child in self.button_frame.winfo_children():
                    child.destroy()
                self.data_list = read_data(self.master.key)
                self.create_description_list()
                self.current_index = -1

            # if(delete_data()){
            # print("Entry deleted!")
            # }

        else:
            print("Deletion canceled.")

    def confirm_choice(self, message, title):
        return Messagebox.yesno(message=message, title=title, parent=self)

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
        self.current_index = index
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

    def toggle_update_entry_password(self):
        entry_id = self.data_list[self.current_index].get('id')
        update_window = UpdateWindow(self.master, entry_id)
        update_window.grab_set()
        update_window.wait_window()
        self.data_list = []
        for child in self.button_frame.winfo_children():
            child.destroy()
        self.data_list = read_data(self.master.key)
        self.create_description_list()
        self.current_index = -1

    def search(self):
        for child in self.button_frame.winfo_children():
            child.destroy()

        if self.search_var.get() == "":
            self.data_list = read_data(self.master.key)
        else:
            self.data_list = [
                x for x in self.data_list if self.search_var.get() in x["description"]
            ]
        self.create_description_list()


class Navigation(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        style = ttk.Style()
        style.configure("nav_button.Link.TButton", font=("Helvetica", 12))
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
            style=style_str,
        )
        options_button.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(options_button)

        password_change_btn = ttk.Button(
            self.master,
            text="Change password",
            state=self.status.get(),
            command=lambda: self.switch_page_callback(ChangeMasterPasswordPage),
            style=style_str,
        )
        password_change_btn.pack(side=bconst.LEFT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(password_change_btn)

        logout_button = ttk.Button(
            self.master,
            text="Logout",
            state=self.status.get(),
            style=style_str,
            command=lambda: self.logout()
        )
        logout_button.pack(side=bconst.RIGHT, padx=x_pad, pady=y_pad)
        self.nav_buttons.append(logout_button)

    def set_navbar_status(self, status):
        for el in self.nav_buttons:
            el.config(state=status)

    def logout(self):
        self.master.key = None
        self.switch_page_callback(LoginPage)


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
        self.create_form_entry(self, "Password", self.password, type_password=True)
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

        self.label = ttk.Label(self, text="Change master password and/or username")
        self.label.pack(pady=10)

        self.error_label = ttk.Label(self, text="", foreground="red")
        self.error_label.pack(pady=10)

        form_frame = ttk.Frame(self)
        form_frame.pack(side=bconst.TOP)
        old_frame = ttk.Frame(form_frame)
        old_frame.pack(side=bconst.LEFT, fill=bconst.BOTH, padx=50, pady=15)
        new_frame = ttk.Frame(form_frame)
        new_frame.pack(side=bconst.LEFT, fill=bconst.BOTH, padx=15, pady=15)

        self.old_username = ttk.StringVar(value="")
        self.old_password = ttk.StringVar(value="")

        self.create_form_entry(old_frame, "Old Username", self.old_username)
        self.create_form_entry(old_frame, "Old Password", self.old_password, type_password=True, anchor="nw")

        self.new_username = ttk.StringVar(value="")
        self.new_password = ttk.StringVar(value="")
        self.confirm_new_password = ttk.StringVar(value="")

        self.create_form_entry(new_frame, "New Username", self.new_username)
        self.create_form_entry(new_frame, "New Password", self.new_password, type_password=True)
        self.create_form_entry(new_frame, "Confirm New Password", self.confirm_new_password, type_password=True)

        self.create_buttonbox()

    def on_submit(self):
        # TODO: password length and complexity checks for new passwords

        choice = self.confirm_choice("Confirm Master Password & Username change", "Change Master Password & Username")

        if choice != "Yes":
            return

        new_username = self.new_username.get()
        new_password = self.new_password.get()
        confirm_new_password = self.confirm_new_password.get()

        old_username = self.old_username.get()
        old_password = self.old_password.get()

        if new_password != confirm_new_password:
            self.error_label.config(text="New password does not match the Confirm New password field!")
            self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))
            return

        success, new_key, error = change_login_password(
            old_username,
            old_password,
            new_username,
            new_password,
        )

        if success:
            self.master.key = new_key
            self.label.config(text="New Username and Password set successfully!")
            self.old_password.set("")
            self.old_username.set("")
            self.new_username.set("")
            self.new_password.set("")
            self.confirm_new_password.set("")

        if error:
            self.error_label.config(text=error)
            self.after(ERROR_MSG_TIME, lambda: self.error_label.config(text=""))

    def on_cancel(self):
        self.switch_page_callback(DataPanel)


class MainApplication(ttk.Window):
    def __init__(self, app_config):
        self.app_config = app_config
        theme = app_config.get("ui_theme", "darkly")
        super().__init__(themename=theme)
        db_init()
        self.title("Password manager")
        self.geometry("800x400+100+100")

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
