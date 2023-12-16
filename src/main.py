from ui import MainApplication
from handle_data import read_config


def main():
    """
    Main function.
    """
    app_config = read_config()
    app = MainApplication(app_config)
    app.mainloop()


if __name__ == "__main__":
    main()
