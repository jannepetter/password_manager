import ttkbootstrap as ttk
import ttkbootstrap.constants as bconst
from handle_data import login, read_data,write_data, db_init
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.dialogs import Messagebox
import pyperclip

def create_button(text,call_back):
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


    def create_form_entry(self,master, label, variable,type_password=False, width=20,buttons=[],anchor="center"):
        """Create a single form entry"""
        container = ttk.Frame(master)
        container.pack(anchor=anchor,pady=5)

        lbl = ttk.Label(master=container, text=label, width=10)
        lbl.pack(anchor="nw", padx=5)

        ent = ttk.Entry(master=container, textvariable=variable,width=width)
        if type_password:
            ent = ttk.Entry(master=container, textvariable=variable,show="*",width=width)

        ent.pack(side=bconst.LEFT, padx=5)
        for el in buttons:
            el.pack(in_=container, side=bconst.LEFT, padx=5)

        return ent

    def on_submit(self):
        pass

    def on_cancel(self):
        pass


class LoginPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        self.label = ttk.Label(self, text="Login to your password manager!")
        self.label.pack(pady=15)
        self.error_label = ttk.Label(self, text="", foreground="red")
        self.error_label.pack(pady=2)

        self.username = ttk.StringVar(value="")
        self.password = ttk.StringVar(value="")

        self.create_form_entry(self,"Username", self.username)
        self.create_form_entry(self,"Password", self.password,type_password=True)
        self.create_buttonbox()

    def on_submit(self):
        """Submits login details"""

        self.master.key = login(
            self.password.get(),
            self.username.get()
            )

        if self.master.key:
            self.show_data_page()

        self.error_label.config(text="Wrong username or password!")
        self.after(2000, lambda:self.error_label.config(text=""))
        self.username.set("")
        self.password.set("")

    def on_cancel(self):
        """Cancel and close the application."""
        self.quit()

    def show_data_page(self):
        self.switch_page_callback(DataPanel)

 

class DataPanel(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)
        self.search_frame = ttk.Frame(self)
        self.search_frame.pack(side=bconst.TOP,fill=bconst.X)
        self.search_var = ttk.StringVar(value="")
        btn = create_button("search",self.search)
        self.create_form_entry(self.search_frame,"Search",self.search_var,anchor="w",buttons=[btn])

        self.common_frame = ttk.Frame(self)
        self.common_frame.pack(side=bconst.TOP,fill=bconst.X)
        self.button_frame = ScrolledFrame(self.common_frame, autohide=True)
        # self.button_frame.grid(row=0, column=0, padx=5, pady=10)
        self.button_frame.pack(side=bconst.LEFT,padx=5, fill=bconst.BOTH)

        # Create a frame for details
        self.details_frame = ttk.Frame(self.common_frame)
        # self.details_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.details_frame.pack(side=bconst.LEFT,padx=30)
        anchor = "w"

        self.entry_description_var = ttk.StringVar(value="")
        copy_desc_btn = create_button(
            "copy",
            lambda:self.copy_to_clipboard(self.entry_description_var.get())
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
            lambda:self.copy_to_clipboard(self.entry_username_var.get())
            )
        self.create_form_entry(
            self.details_frame,
            "Username",self.entry_username_var,
            buttons=[copy_uname_btn],
            anchor=anchor,
            )

        self.entry_password_var = ttk.StringVar(value="")
        copy_passw_btn = create_button(
            "copy",
            lambda:self.copy_to_clipboard(self.entry_password_var.get())
        )
        toggle_show_passw_btn = create_button(
            "show",
            lambda:self.toggle_show_entry_password()
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

        self.data_list = read_data(self.master.key)
        self.create_description_list()

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

    
    def copy_to_clipboard(self,variable):
        pyperclip.copy(variable)

    def toggle_show_entry_password(self):
        current_show_state = self.password_entry.cget("show")
        new_show_state = "" if current_show_state == "*" else "*"
        self.password_entry.config(show=new_show_state)

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
        # disable nav bar before login
        # status = bconst.DISABLED
        status = ""
        width = 6
        x_pad = 5
        y_pad = 5
        data_button = ttk.Button(
            self.master, 
            text="Data", 
            width=width,
            state=status,
            command=lambda: self.switch_page_callback(DataPanel)
            )
        data_button.pack(side=bconst.LEFT, padx=x_pad,pady=y_pad)

        add_button = ttk.Button(
            self.master, 
            text="Add", 
            width=width,
            state=status,
            command=lambda: self.switch_page_callback(AddDataPage)
            )
        add_button.pack(side=bconst.LEFT, padx=x_pad,pady=y_pad)


        options_button = ttk.Button(
            self.master, 
            text="Options", 
            width=width,
            state=status,
            )
        options_button.pack(side=bconst.LEFT, padx=x_pad,pady=y_pad)

        logout_button = ttk.Button(
            self.master, 
            text="Logout", 
            width=width,
            state=status,
            )
        logout_button.pack(side=bconst.RIGHT, padx=x_pad,pady=y_pad)

    def some_func(self,page):
        self.switch_page_callback(page)
        print('testing',page)

class AddDataPage(SubPage):
    def __init__(self, master, switch_page_callback):
        super().__init__(master, switch_page_callback)

        self.label = ttk.Label(self, text="Create a new data entry")
        self.label.pack(pady=10)

        self.description= ttk.StringVar(value="")
        self.username = ttk.StringVar(value="")
        self.password = ttk.StringVar(value="")

        self.create_form_entry(self,"Description", self.description)
        self.create_form_entry(self,"Username", self.username)
        self.create_form_entry(self,"Password", self.password,type_password=True)
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
        print('data written in db')

    def on_cancel(self):
        self.switch_page_callback(DataPanel)

 


class MainApplication(ttk.Window):
    def __init__(self, theme):
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





    