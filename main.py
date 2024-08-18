from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# 32 byte uzunluğunda sabit bir anahtar oluşturma
def generate_key_from_master_key(master_key):
    # master_key'i SHA-256 hash fonksiyonu ile 32 byte uzunluğunda bir anahtar oluşturma
    digest = hashlib.sha256(master_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    try:
        decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        return None

def save_and_encrypt():
    title = secret_title_entry.get()
    message = secret_text_entry.get("1.0", END).strip()
    master_key = secret_master_key_entry.get()

    if not title or not message or not master_key:
        messagebox.showerror("Error", "Fill in all fields")
        return

    # Master key'den şifreleme anahtarı üretme
    key = generate_key_from_master_key(master_key)

    # Mesajı şifrele
    encrypted_message = encrypt_message(message, key)

    # Şifrelenmiş mesajı ve başlığı secretnotes.txt dosyasına ekleme
    try:
        with open("secretnotes.txt", "a") as file:
            file.write(f"{title}\n")
            file.write(f"{encrypted_message.decode()}\n")
        messagebox.showinfo("Success", "Message has been saved and encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save the message: {str(e)}")

    # Alanları temizleme işlemi
    secret_title_entry.delete(0, END)
    secret_text_entry.delete("1.0", END)
    secret_master_key_entry.delete(0, END)

def decrypt():
    title = secret_title_entry.get()
    encrypted_message = secret_text_entry.get("1.0", END).strip()
    master_key = secret_master_key_entry.get()

    if not title or not encrypted_message or not master_key:
        messagebox.showerror("Error", "All fields are required!")
        return

    # Master key'den şifre çözme anahtarı üretme
    key = generate_key_from_master_key(master_key)

    try:
        with open("secretnotes.txt", "r") as file:
            lines = file.readlines()

        # Başlık ve şifrelenmiş mesajı eşleştirme
        for i in range(0, len(lines), 2):
            stored_title = lines[i].strip()
            stored_encrypted_message = lines[i+1].strip()

            if stored_title == title and stored_encrypted_message == encrypted_message:
                # Mesajı çöz
                decrypted_message = decrypt_message(encrypted_message.encode(), key)

                if decrypted_message:
                    secret_text_entry.delete("1.0", END)
                    secret_text_entry.insert(END, decrypted_message)
                    return
                else:
                    messagebox.showerror("Error", "Decryption failed! Wrong Master Key.")
                    return

        messagebox.showerror("Error", "No matching encrypted message found!")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt the message: {str(e)}")

def main():
    window = Tk()
    window.title("Secret Notes")

    image = PhotoImage(file="topsecret.png")
    image_label = Label(window, image=image, pady=20, padx=20)
    image_label.pack()

    secret_title_label = Label(window, text="Enter Your Title")
    secret_title_label.pack()

    global secret_title_entry
    secret_title_entry = Entry(window)
    secret_title_entry.pack()

    secret_text_label = Label(window, text="Enter Your Secret / Encrypted Message")
    secret_text_label.pack()

    global secret_text_entry
    secret_text_entry = Text(window, width=40, height=10)
    secret_text_entry.pack()

    secret_master_key_label = Label(window, text="Enter Master Key")
    secret_master_key_label.pack()

    global secret_master_key_entry
    secret_master_key_entry = Entry(window)
    secret_master_key_entry.pack()

    save_and_encrypt_button = Button(window, text="Save And Encrypt", command=save_and_encrypt)
    save_and_encrypt_button.pack()

    decrypt_button = Button(window, text="Decrypt", command=decrypt)
    decrypt_button.pack()

    window.mainloop()

main()