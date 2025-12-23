import tkinter as tk
from gui_app import ChatClientGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()