import tkinter as tk
from tkinter import messagebox
from PIL import Image,ImageTk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
import smtplib
import sqlite3
import re
import random
import threading


timer_running = True


def update_timer(label, seconds_left):
    if seconds_left > 0 and timer_running:
        label.config(text=f"OTP expires in {seconds_left} seconds")
        seconds_left -= 1
        label.after(1000, update_timer, label, seconds_left)
    else:
        label.config(text="OTP has expired!", fg="red")


def create_database():
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email_id TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
                )''')
    con.commit()
    con.close()


def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def clear_screen():
    for widgets in main_frame.winfo_children():
        widgets.destroy()


def cancel_action():
    global timer_running
    timer_running = False
    login_screen()


def on_closing():
    global timer_running
    timer_running = False
    root.destroy()


def change_password():
    new_password = n_pwd.get()
    confirm_password = c_pwd.get()

    if new_password == "Enter a Password" or confirm_password == "Confirm Password":
        messagebox.showerror("Error", "Please enter and confirm your password.")
        return

    if new_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match. Please try again.")
        return

    if len(new_password) < 6:
        messagebox.showerror("Error", "Password should be at least 6 characters long.")
        return

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE email_id = ?", (new_password, user_email))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password updated successfully!")
    login_screen()


def change_password_screen():
    clear_screen()
    global n_pwd, c_pwd

    tk.Label(main_frame, text="ACCOUNT RECOVERY", font=("dubai", 15), bg="#00cc66",
             fg="white").place(rely=0, relwidth=1, relheight=0.12)
    tk.Label(main_frame, text="Create a New Password", font=("consolas", 15), bg="#e2eaf4",
             fg="#060270").place(rely=0.2, relwidth=1)

    def create_placeholder(entry_widget, placeholder_text, is_password=False):
        entry_widget.insert(0, placeholder_text)

        def on_focus_in(event):
            if entry_widget.get() == placeholder_text:
                entry_widget.delete(0, tk.END)
                if is_password:
                    entry_widget.config(show="*")

        def on_focus_out(event):
            if entry_widget.get() == '':
                entry_widget.insert(0, placeholder_text)
                if is_password:
                    entry_widget.config(show="")

        entry_widget.bind('<FocusIn>', on_focus_in)
        entry_widget.bind('<FocusOut>', on_focus_out)

    n_pwd = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    n_pwd.place(relx=0.3, rely=0.32, relwidth=0.4, relheight=0.075)
    create_placeholder(n_pwd, "Enter a Password", is_password=True)

    c_pwd = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    c_pwd.place(relx=0.3, rely=0.45, relwidth=0.4, relheight=0.075)
    create_placeholder(c_pwd, "Confirm Password", is_password=True)

    submit_btn = tk.Button(main_frame, text="SUBMIT", font=("dubai", 15), bg="#339966", fg="white",
                           bd=2, command=change_password)
    submit_btn.place(relx=0.375, rely=0.6, relwidth=0.25, relheight=0.08)

    cancel_btn = tk.Button(main_frame, text="CANCEL", font=("dubai", 15), bg="#e2eaf4", fg="#ff471a",
                           bd=1, relief="solid", command=cancel_action)
    cancel_btn.place(relx=0.375, rely=0.75, relwidth=0.25, relheight=0.08)



def verify_otp():
    global otp
    entered_otp = str(otp_input.get())

    if otp is None:
        messagebox.showerror("Error", "OTP has expired. Please request a new OTP.")
        return

    if entered_otp == otp:
        messagebox.showinfo("Success", "OTP verified successfully!")
        change_password_screen()
    else:
        messagebox.showerror("Error", "Invalid OTP. Please try again.")


def reset_otp():
    global otp
    otp = None


def resend_otp():
    global otp
    random_val = random.randint(10001, 99999)
    otp = str(random_val)

    email_thread = threading.Thread(target=send_otp_email, args=(user_email, otp))
    email_thread.start()

    messagebox.showinfo("Resent", "A new OTP has been sent to your email.")


def send_otp_email(user_email, otp):
    global timer_running
    try:
        smtp = smtplib.SMTP('smtp.gmail.com', 587)
        smtp.ehlo()
        smtp.starttls()
        admin_email = config('EMAIL_ID')
        app_password = config('APP_PASSWORD')
        smtp.login(admin_email, app_password)

        def message(subject="OTP Request", text=""):
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg.attach(MIMEText(text))
            return msg
        
        msg = message("Reset Password", f"Dear user,\nYour OTP is: {otp}")
        to = [user_email]
        smtp.sendmail(from_addr=admin_email, to_addrs=to, msg=msg.as_string())
        smtp.quit()

        timer_running = True
        timer_label = tk.Label(main_frame, text="OTP expires in 120 seconds", font=("dubai", 15), fg="brown", bg="#e2eaf4")
        timer_label.place(rely=0.66, relwidth=1)
        update_timer(timer_label, 120)

        otp_timer = threading.Timer(120.0, reset_otp)
        otp_timer.start()

    except Exception as e:
        messagebox.showerror("Error", "Failed to send OTP!")
        print("Error:", e)
        tk.Label(main_frame, text="Failed to send OTP. Please Try Again!", font=("dubai", 15), fg="red", bg="#e2eaf4").place(rely=0.66, relwidth=1)



def account_recovery():
    global otp, user_email
    usr_input = user_input.get()
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT email_id FROM users WHERE username = ? OR email_id = ?", (usr_input, usr_input))
    result = cursor.fetchone()
    conn.close()

    random_val = random.randint(10001, 99999)
    otp = str(random_val)

    if result:
        forgot_password_screen2()
        user_email = result[0]
        email_thread = threading.Thread(target=send_otp_email, args=(user_email, otp))
        email_thread.start()
        resend_button = tk.Button(main_frame, text="Resend OTP", font=("dubai", 12), fg="#060270", bg="#e2eaf4", bd=0, command=resend_otp)
        resend_button.place(relx=0.35, rely=0.82, relwidth=0.3, relheight=0.08)

    else:
        messagebox.showerror("Error", "Invalid credentials")
        return
    

def forgot_password_screen2():
    clear_screen()
    global otp_input

    tk.Label(main_frame, text="ACCOUNT RECOVERY", font=("dubai", 15), bg="#00cc66", fg="white").place(rely=0, relwidth=1, relheight=0.12)
    tk.Label(main_frame, text="Enter OTP:", font=("consolas", 15), bg="#e2eaf4", fg="#060270").place(relx=0.22, rely=0.2)
    
    otp_input = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    otp_input.place(relx=0.5, rely=0.2, relwidth=0.28, relheight=0.07)

    submit_btn = tk.Button(main_frame, text="SUBMIT", font=("dubai", 15), bg="#339966", fg="white", bd=2, command=verify_otp)
    submit_btn.place(relx=0.375, rely=0.33, relwidth=0.25, relheight=0.08)

    cancel_btn = tk.Button(main_frame, text="CANCEL", font=("dubai", 15), bg="#e2eaf4", fg="#ff471a", bd=1, relief="solid", command=login_screen)
    cancel_btn.place(relx=0.375, rely=0.5, relwidth=0.25, relheight=0.08)

    tk.Label(main_frame, text="Sending an OTP to your registered email...", font=("dubai", 15), fg="brown", bg="#e2eaf4").place(rely=0.66, relwidth=1)



def forgot_password_screen1():
    clear_screen()
    global user_input
    tk.Label(main_frame, text="ACCOUNT RECOVERY", font=("dubai", 15), bg="#00cc66",
             fg="white").place(rely=0, relwidth=1, relheight=0.12)
    tk.Label(main_frame, text="Enter your Username or Email", font=("dubai", 15), bg="#e2eaf4",
             fg="#060270").place(rely=0.2, relwidth=1)
    user_input = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    user_input.place(relx=0.25, rely=0.3, relwidth=0.5, relheight=0.07)
    next_btn = tk.Button(main_frame, text="NEXT", font=("dubai", 15), bg="#339966", fg="white",
                     bd=2,command=account_recovery)
    next_btn.place(relx=0.375, rely=0.43, relwidth=0.25, relheight=0.08)
    cancel_btn = tk.Button(main_frame, text="CANCEL", font=("dubai", 15), bg="#e2eaf4", fg="#ff471a",
                     bd=1, relief="solid", command=login_screen)
    cancel_btn.place(relx=0.375, rely=0.6, relwidth=0.25, relheight=0.08)


def user_registration():
    username = user_name.get()
    firstname = first_name.get()
    lastname = last_name.get()
    emailid = email_id.get()
    password = pswd.get()
    cnfpswd = cnf_pswd.get()

    if not (username and password and firstname and lastname and emailid and cnfpswd):
        messagebox.showwarning("Input Error", "Values cannot be blank!")
        return

    def check_spaces(input_field):
        if " " in input_field:
            messagebox.showwarning("Input Error", "Spaces are not allowed")
            return True
        return False

    if check_spaces(username) or check_spaces(firstname) or check_spaces(lastname) or check_spaces(emailid) or check_spaces(password) or check_spaces(cnfpswd):
        return

    if len(username) < 6 or len(username) > 15:
        messagebox.showwarning("Input Error", "Username must be between 6 and 15 characters!")
        return

    if len(password) < 8 or len(password) > 15:
        messagebox.showwarning("Input Error", "Password must be between 8 and 15 characters!")
        return

    if len(firstname) < 3 or len(firstname) > 25:
        messagebox.showwarning("Input Error", "First name must be between 3 and 25 characters!")
        return

    if len(lastname) < 3 or len(lastname) > 25:
        messagebox.showwarning("Input Error", "Last name must be between 3 and 25 characters!")
        return

    if not validate_email(emailid):
        messagebox.showwarning("Input Error", "Invalid email format!")
        return

    if password != cnfpswd:
        messagebox.showwarning("Input Error", "Passwords do not match!")
        return

    con = sqlite3.connect("app.db")
    cur = con.cursor()
    try:
        cur.execute('''INSERT INTO users (username, first_name, last_name, email_id, password) 
                       VALUES (?, ?, ?, ?, ?)''', 
                       (username, firstname, lastname, emailid, password))
        con.commit()
        messagebox.showinfo("Success", "User registered successfully!")
        login_screen()
        
    except sqlite3.IntegrityError:
        messagebox.showwarning("Error", "Username or email already exists!")
    finally:
        con.close()


def register_screen():
    clear_screen()
    global first_name, last_name, user_name, email_id, pswd, cnf_pswd

    def focus_next_widget(event, next_widget):
        next_widget.focus_set()
        return "break"

    tk.Label(main_frame, text="First Name", font=("dubai", 14), bg="#00b365",
             fg="white").place(relx=0, rely=0, relwidth=0.4, relheight=0.1)
    first_name = tk.Entry(main_frame, font=("dubai", 14))
    first_name.place(relx=0.4, rely=0, relwidth=0.6, relheight=0.1)
    
    first_name.bind("<Return>", lambda event: focus_next_widget(event, last_name))

    tk.Label(main_frame, text="Last Name", font=("dubai", 14), bg="#00cc66",
             fg="white").place(relx=0, rely=0.1, relwidth=0.4, relheight=0.1)
    last_name = tk.Entry(main_frame, font=("dubai", 14))
    last_name.place(relx=0.4, rely=0.1, relwidth=0.6, relheight=0.1)

    last_name.bind("<Return>", lambda event: focus_next_widget(event, user_name))

    tk.Label(main_frame, text="Username", font=("dubai", 14), bg="#00b365",
             fg="white").place(relx=0, rely=0.2, relwidth=0.4, relheight=0.1)
    user_name = tk.Entry(main_frame, font=("dubai", 14))
    user_name.place(relx=0.4, rely=0.2, relwidth=0.6, relheight=0.1)

    user_name.bind("<Return>", lambda event: focus_next_widget(event, email_id))

    tk.Label(main_frame, text="Email ID", font=("dubai", 14), bg="#00cc66",
             fg="white").place(relx=0, rely=0.3, relwidth=0.4, relheight=0.1)
    email_id = tk.Entry(main_frame, font=("dubai", 14))
    email_id.place(relx=0.4, rely=0.3, relwidth=0.6, relheight=0.1)

    email_id.bind("<Return>", lambda event: focus_next_widget(event, pswd))

    tk.Label(main_frame, text="Password", font=("dubai", 14), bg="#00b365",
             fg="white").place(relx=0, rely=0.4, relwidth=0.4, relheight=0.1)
    pswd = tk.Entry(main_frame, font=("dubai", 14), show="*")
    pswd.place(relx=0.4, rely=0.4, relwidth=0.6, relheight=0.1)

    pswd.bind("<Return>", lambda event: focus_next_widget(event, cnf_pswd))

    tk.Label(main_frame, text="Confirm Password", font=("dubai", 14), bg="#00cc66",
             fg="white").place(relx=0, rely=0.5, relwidth=0.4, relheight=0.1)
    cnf_pswd = tk.Entry(main_frame, font=("dubai", 14), show="*")
    cnf_pswd.place(relx=0.4, rely=0.5, relwidth=0.6, relheight=0.1)

    cnf_pswd.bind("<Return>", lambda event: user_registration())

    register_btn = tk.Button(main_frame, text="REGISTER", font=("dubai", 16), bg="#339966", fg="white", command=user_registration)
    register_btn.place(relx=0.35, rely=0.68, relwidth=0.3, relheight=0.1)

    login_page_btn = tk.Button(main_frame, text="CANCEL", font=("dubai", 14), bg="#e2eaf4", fg="#ff471a", relief="solid", bd=1, command=login_screen)
    login_page_btn.place(relx=0.39, rely=0.85, relwidth=0.22, relheight=0.08)


def user_logout():
    message = messagebox.askyesno("Logout", "Are you sure to logout?")
    if message:
        login_screen()

def welcome_screen():
    clear_screen()
    first_name = user_info.get("first_name")
    last_name = user_info.get("last_name")

    image2 = Image.open("images/thumbsup.png")
    resize_image2 = image2.resize((250, 250))
    test2 = ImageTk.PhotoImage(resize_image2)
    label2 = tk.Label(main_frame, image=test2, bg="#e2eaf4")
    label2.image = test2
    label2.place(rely=0.22, relwidth=1)
    
    tk.Label(main_frame, text=f"Welcome, {first_name} {last_name}".title(), font=("dubai", 12), fg="brown", bg="#e2eaf4").place(relx=0.02, rely=0.02)

    tk.Label(main_frame, text="You have successfully logged in!", font=("dubai", 15), fg="darkgreen", bg="#e2eaf4").place(rely=0.15, relwidth=1)
    tk.Button(main_frame, text="LOGOUT", font=("dubai", 15, "underline"), fg="#060270", bg="#e2eaf4", bd=0, command=user_logout).place(relx=0.375, rely=0.8, relheight=0.1, relwidth=0.25)



def user_login():
    login_input = uname.get()
    password = pwd.get()

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users 
        WHERE (username = ? OR email_id = ?) AND password = ?
    """, (login_input, login_input, password))

    result = cursor.fetchone()
    conn.close()

    if result:
        global user_info
        columns = [desc[0] for desc in cursor.description]
        user_info = dict(zip(columns, result))
        welcome_screen()
    else:
        messagebox.showerror("Error", "Invalid credentials")


def login_screen():
    clear_screen()
    global uname, pwd

    image1 = Image.open("images/login.png")
    resize_image1 = image1.resize((120, 120))
    test1 = ImageTk.PhotoImage(resize_image1)
    label1 = tk.Label(main_frame, image=test1, bg="#e2eaf4")
    label1.image = test1
    label1.place(rely=0.05, relwidth=1)

    def create_placeholder(entry_widget, placeholder_text, is_password=False):
        entry_widget.insert(0, placeholder_text)

        def on_focus_in(event):
            if entry_widget.get() == placeholder_text:
                entry_widget.delete(0, tk.END)
                if is_password:
                    entry_widget.config(show="*")

        def on_focus_out(event):
            if entry_widget.get() == '':
                entry_widget.insert(0, placeholder_text)
                if is_password:
                    entry_widget.config(show="")

        entry_widget.bind('<FocusIn>', on_focus_in)
        entry_widget.bind('<FocusOut>', on_focus_out)

    uname = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    uname.place(relx=0.25, rely=0.37, relwidth=0.5, relheight=0.075)

    pwd = tk.Entry(main_frame, font=("dubai", 13), fg="#595959", relief="solid", bd=1)
    pwd.place(relx=0.25, rely=0.5, relwidth=0.5, relheight=0.075)

    create_placeholder(uname, "Enter Username or Email")
    create_placeholder(pwd, "Enter Password", is_password=True)

    login_btn = tk.Button(main_frame, text="LOGIN", font=("dubai", 15), bg="#339966", fg="white",
                          bd=2, command=user_login)
    login_btn.place(relx=0.375, rely=0.63, relwidth=0.25, relheight=0.08)

    forgot_pwd_btn = tk.Button(main_frame, text="Forgot Password?", font=("dubai", 12), bd=0, bg="#e2eaf4", fg="#060270",
                               command=forgot_password_screen1)
    forgot_pwd_btn.place(relx=0.35, rely=0.77, relwidth=0.3, relheight=0.08)

    tk.Label(main_frame, text="Do not have an account?", font=("dubai", 12), bg="#e2eaf4",
             fg="black").place(relx=0.24, rely=0.87)

    register_btn = tk.Button(main_frame, text="Register", font=("dubai", 12), bd=0, bg="#e2eaf4", fg="#060270",
                             command=register_screen)
    register_btn.place(relx=0.61, rely=0.87, relwidth=0.15, relheight=0.08)



root = tk.Tk()

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

window_width = 500
window_height = 500

x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)

root.geometry(f"{window_width}x{window_height}+{x}+{y}")

root.resizable(0,0)

root_title = "Authentication App"

root.title(root_title)
root.config(bg="lightgreen")
main_frame = tk.Frame(root, bg="#e2eaf4", bd=5, relief="ridge")
main_frame.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

create_database()
login_screen()

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()