import tkinter as tk
from gui.connection_test import *
from gui.software_details import *
from gui.chat import *

class ChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("主界面")
        self.master.geometry("400x300")

        # 创建主界面内容
        self.label = tk.Label(master, text="简单的聊天软件", font=("Arial", 20))
        self.label.pack(pady=20)

        # 创建选项按钮
        self.btn_software_details = tk.Button(master, text="软件详情", command=show_software_details)
        self.btn_software_details.pack(pady=5)

        self.btn_connection_test = tk.Button(master, text="连接测试与状态", command=show_connection_test)
        self.btn_connection_test.pack(pady=5)

        self.btn_chat = tk.Button(master, text="聊天框", command=start_chat)
        self.btn_chat.pack(pady=5)
        