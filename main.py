import tkinter as tk
import gui.main_window as ui

if __name__ == "__main__":
    root = tk.Tk()
    app = ui.ChatApp(root)
    root.mainloop()