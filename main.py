from tkinter import *
import tkinter
from tkinter import messagebox
import PIL
from PIL import ImageTk
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def saveAndEncryptNotes():
    title = titleEntry.get()
    message = textbox.get("1.0", END)
    masterSecret = masterKey.get()

    if len(title) == 0 or len(message) == 0 or len(masterSecret) == 0:
        messagebox.showinfo(title="ERROR!",message="Please enter all info.")
    else:
        messageEncrypted = encode(masterSecret,message)
        try:
            with open("mysecret.txt","a") as dataFile:
                dataFile.write(f"\n{title}\n{messageEncrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","r") as dataFile:
                dataFile.write(f"\n{title}\n{messageEncrypted}")
        finally:
            titleEntry.delete(0,END)
            masterKey.delete(0,END)
            textbox.delete("1.0",END)

def decryptNotes():
    messageEncrypted = textbox.get("1.0",END)
    masterSecret = masterKey.get()

    if len(messageEncrypted) == 0 or len(masterSecret) == 0:
        messagebox.showinfo(title="ERROR!", message="Please enter all info.")

    else:
        try:
            decryptedMessage = decode(masterSecret, messageEncrypted)
            textbox.delete("1.0",END)
            textbox.insert("1.0", decryptedMessage)
        except:
            messagebox.showinfo(title="ERROR!", message="Please enter encrypted text.")

window = tkinter.Tk()
window.title("Secret Notes")
window.wm_minsize(width=10, height=600)
FONT = ("Verdana",10,"normal")

image = PIL.Image.open(r"C:\Users\Lenovo\Desktop\top.png")
img = ImageTk.PhotoImage(image)
lbl = Label(image=img,width=350,height=200)
lbl.pack()


lbl2 = Label(text="Enter your title",font=FONT)
lbl2.pack()

titleEntry = Entry(width=35)
titleEntry.pack()

lbl3 = Label(text="Enter your secret",font=FONT)
lbl3.pack()

textbox = Text(width=40,height=20)
textbox.pack()

lbl4 = Label(text="Enter master key ",font=FONT)
lbl4.pack()

masterKey = Entry(width=35)
masterKey.pack()

saveBtn = Button(text="Save & Encrypt", command=saveAndEncryptNotes)
saveBtn.pack()

decryptBtn = Button(text="Decrypt", command=decryptNotes)
decryptBtn.pack()

window.mainloop()