import tkinter as tk
import chat.client

chat.client.login_to_chatui()

def start_chat():
    chat_window = tk.Toplevel()
    chat_window.title("聊天窗口")
    chat_window.geometry("400x300")

    # 创建聊天界面的内容
    chat_label = tk.Label(chat_window, text="聊天功能尚未实现", font=("Arial", 16))
    chat_label.pack(pady=20)

    # 可以在这里添加更多的聊天功能，例如输入框、发送按钮等
    input_frame = tk.Frame(chat_window)
    input_frame.pack(pady=10)

    input_entry = tk.Entry(input_frame, width=40)
    input_entry.pack(side=tk.LEFT, padx=5)

    send_button = tk.Button(input_frame, text="发送", command=lambda: print("发送消息:", input_entry.get()))
    send_button.pack(side=tk.LEFT)