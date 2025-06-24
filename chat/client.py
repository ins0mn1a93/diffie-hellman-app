import tkinter as tk
import threading
import utils.sockConnect

def login_to_chatui():
    root = tk.Tk()
    root.title("个人信息填写")
    root.geometry('300x150')

    nickname = tk.StringVar()

    def info_fill():
        name = nickname.get()
        if not name:
            tk.messagebox.showerror("错误", "昵称不能为空")
        if len(name) > 20:
            tk.messagebox.showerror("错误", "昵称长度不能超过20个字符")
        else:
            root.destroy()
            # s = utils.sockConnect.cliSocket("127.0.0.1", 12345)
            # s.send(name.encode('utf-8'))
            tk.messagebox.showinfo("成功", "昵称已保存")
    
    tk.Button(root, text = "登录", command = info_fill, width = 8, height = 1).place(x=100, y=90, width=100, height=35)
    tk.Label(root, text='请输入昵称', font=('Fangsong',12)).place(x=10, y=20, height=50, width=80)
    tk.Entry(root, textvariable = nickname, font=('Fangsong', 11)).place(x=100, y=30, height=30, width=180)
 
    root.mainloop()