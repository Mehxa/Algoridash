from tkinter import *
from PIL import ImageTk, Image
from MyCryptoPackage import MyCaesarCipher, MyRailFence, MySimpleColumnarTransposition, MyMonoalphabetCipher, MyVernamCipher, MyAes, MyDiffieHellman


# The main body of the app, just like <body>
class Root(Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Algoridash")
        self.canvas = Canvas(self, height=575, width=925, bg="purple")
        self.canvas.pack(fill=BOTH, expand=TRUE)
        self.canvas.bind("<Configure>", self.resize)
        self.img = ImageTk.PhotoImage(
            Image.open("images/background.png")
        )
        self.canvas_img = self.canvas.create_image(0, 0, anchor="nw", image=self.img)
        self.home_page = Frame(self.canvas, bg="#8f258f")
        home_page = self.home_page
        home_page.place(relx=0.3, rely=0.25, relwidth=0.4, relheight=0.45)
        Title = Label(home_page, text="Algoridash", font=("Montserrat", 26), bg="#8f258f", fg="white")
        Title.place(relx=0.2, rely=0.03, relwidth=0.6)
        Lesson_Button = Button(home_page, text="Security Management Practices", bg="indian red", fg="white", command=self.to_lesson)
        Algoridash = Button(home_page, text="Encryption Algorithms", bg="chocolate", fg="white", command=self.to_algorithms)
        Lesson_Button.place(relx=0.25, rely=0.3, relwidth=0.5, relheight=0.2)
        Algoridash.place(relx=0.25, rely=0.6, relwidth=0.5, relheight=0.2)

        # Lesson body
        self.lesson_body = Frame(self.canvas, bg="#8f258f")
        lesson_body = self.lesson_body
        Home_Button = Button(lesson_body, text="Home", bg="brown", fg="white", command=self.lesson_to_home)
        Home_Button.place(relx=0, rely=0)
        top_title = Label(lesson_body, text="4 Characteristics of a good Security Policy", bg="#8f258f", fg="white", font=("Montserrat", 16))
        # display_characteristic = Frame(lesson_body, bg="indian red")
        # display_characteristic.place(relx=0.25, rely=0.07, relwidth=0.5, relheight=0.3)
        self.button_title = Label(lesson_body, text="Affordability", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 16))
        self.title_definition = Label(lesson_body, text="Cost and Effort in implementation", bg="#8f258f", fg="white", font=("Arial", 12))
        self.explanation = Label(lesson_body, text="The security policy should not be too costly and \nincur too much effort to implement", bg="#8f258f", fg="white")
        self.button_title.place(relx=0.4, rely=0.24, relwidth=0.2)
        self.title_definition.place(relx=0.2, rely=0.3, relwidth=0.6)
        self.explanation.place(relx=0.2, rely=0.36, relwidth=0.6)
        button_Affordability = Button(lesson_body, text="Affordability", bg="indian red", fg="white", command=self.change_to_affordability)
        button_Functionality = Button(lesson_body, text="Functionality", bg="indian red", fg="white", command=self.change_to_functionality)
        button_Cultural_Issues = Button(lesson_body, text="Cultural Issues", bg="indian red", fg="white", command=self.change_to_cultural_issues)
        button_Legality = Button(lesson_body, text="Legality", bg="indian red", fg="white", command=self.change_to_legality)
        button_Affordability.place(relx=0.22, rely=0.14, relheight=0.08)
        button_Functionality.place(relx=0.4, rely=0.14, relheight=0.08)
        button_Cultural_Issues.place(relx=0.55, rely=0.14, relheight=0.08)
        button_Legality.place(relx=0.75, rely=0.14, relheight=0.08)
        top_title.place(relx=0.205, rely=0.02, relwidth=0.6)

        hr = Frame(lesson_body, bg="chocolate")
        hr.place(relx=0, rely=0.4995, relheight=0.01, relwidth=1)

        bottom_title = Label(lesson_body, text="Successful implementation of Security Policy", bg="#8f258f", fg="white", font=("Montserrat", 16))
        bottom_title.place(relx=0.1, rely=0.51, relwidth=0.8)

        security_policy_title = Label(lesson_body, text="1. Explain the security policy to all concerned", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 16))
        security_policy_title.place(relx=0.1, rely=0.57, relwidth=0.8)

        responsibilities_title = Label(lesson_body, text="2. Outline everyone's responsibilities", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 12))
        responsibilities_title.place(relx=0.1, rely=0.64, relwidth=0.8)

        simple_language_title = Label(lesson_body, text="3. Use Simple Language in all communications", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 12))
        simple_language_title.place(relx=0.1, rely=0.71, relwidth=0.8)

        Accountability_title = Label(lesson_body, text="4. Establish Accountability", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 12))
        Accountability_title.place(relx=0.1, rely=0.78, relwidth=0.8)

        e_and_p_title = Label(lesson_body, text="5. Provide for exceptions and periodic review", bg="#8f258f", fg="white", font=("Microsoft YaHei UI", 12))
        e_and_p_title.place(relx=0.1, rely=0.85, relwidth=0.8)

        quiz_button = Button(lesson_body, text="Take Quiz", bg="sienna2", fg="white", command=self.quiz)
        quiz_button.place(relx=0.45, rely=0.93, relwidth=0.1)

        # Quiz Stuff
        self.quiz_body = Frame(self.canvas, bg="#8f258f")
        self.quiz_question = Label(self.quiz_body, bg="#8f258f", fg="white", font=("Montserrat", 16))
        self.quiz_question.place(relx=0.1, rely=0.05, relwidth=0.8)
        self.option1_button = Button(self.quiz_body)
        self.option2_button = Button(self.quiz_body)
        self.option3_button = Button(self.quiz_body)
        self.option4_button = Button(self.quiz_body)
        self.feedback = Label(self.quiz_body, bg="#8f258f", fg="white")
        self.next_question = Button(self.quiz_body, text="Next")
        self.option1_button.place(relx=0.3, rely=0.3, relwidth=0.4)
        self.option2_button.place(relx=0.3, rely=0.4, relwidth=0.4)
        self.option3_button.place(relx=0.3, rely=0.5, relwidth=0.4)
        self.option4_button.place(relx=0.3, rely=0.6, relwidth=0.4)
        self.quiz_score = 0

        self.results_body = Frame(self.canvas, bg="#8f258f")
        self.remark = ""
        self.return_home = Button(self.results_body, text="Home", bg="brown", fg="white", command=self.quiz_to_home)
        self.relearn = Button(self.results_body, text="Back to Lesson", bg="indian red", fg="white", command=self.quiz_to_lesson)
        self.algoTime = Button(self.results_body, text="Encryption Methods", bg="chocolate", fg="white", command=self.quiz_to_algorithms)
        self.return_home.place(relx=0.3, rely=0.5, relwidth=0.4)
        self.relearn.place(relx=0.3, rely=0.6, relwidth=0.4)
        self.algoTime.place(relx=0.3, rely=0.7, relwidth=0.4)

        # Main body of the app where encryption input and output done
        self.main_body = Frame(self.canvas, bg="#8f258f")
        main_body = self.main_body
        Home_Button = Button(main_body, text="Home", bg="brown", fg="white", command=self.algorithms_to_home)
        Home_Button.place(relx=0, rely=0)

        selection = Frame(main_body, bg="indian red", pady=5)
        selection.place(relx=0.1, rely=0.03, relwidth=0.35)
        encryption_label = Label(selection, text="Encryption Method:", fg="white", bg="indian red")
        encryption_label.pack()
        encryption_methods = ["Caesar Cipher",
                              "Mono-alphabet Cipher",
                              "Rail Fence Cipher",
                              "Simple Columnar Transposition",
                              "Vernam Cipher",
                              "AES",
                              "Diffie Hellman"]
        self.clicked = StringVar()
        self.clicked.set(encryption_methods[0])
        clicked = self.clicked
        encryption_types = OptionMenu(selection, clicked, *encryption_methods, command=self.change_method)
        encryption_types.config(bg="DarkGoldenRod1")
        encryption_types["menu"].config(bg="chocolate", fg="white")
        encryption_types.pack()

        # AES Stuff
        self.AES_Key_Size_frame = Frame(main_body, bg="indian red", pady=5)
        Key_Size_label = Label(self.AES_Key_Size_frame, text="Key Size(bits):", fg="white", bg="indian red")
        Key_Size_label.pack()
        Key_Sizes = ["128", "192", "256"]
        self.Key_size = StringVar()
        self.Key_size.set(Key_Sizes[0])
        key_size = self.Key_size
        Key_Size_Selection = OptionMenu(self.AES_Key_Size_frame, key_size, *Key_Sizes)
        Key_Size_Selection.config(bg="DarkGoldenRod1")
        Key_Size_Selection["menu"].config(bg="chocolate", fg="white")
        Key_Size_Selection.pack()



        self.special = Frame(main_body, pady=5, bg="indian red")
        self.description = Label(self.special, text="Shift key(digits):", fg="white", bg="indian red")
        description = self.description
        self.special_value = Entry(self.special, justify="center")
        description.pack()
        self.special_value.pack()

        AES_Modes = ["CBC", "CFB", "OFB", "ECB"]
        self.AES_Mode = StringVar()
        self.AES_Mode.set(AES_Modes[0])
        AES_Mode = self.AES_Mode
        self.AES_Mode_Selection = OptionMenu(self.special, AES_Mode, *AES_Modes, command=self.change_method)
        self.AES_Mode_Selection.config(bg="DarkGoldenRod1")
        self.AES_Mode_Selection["menu"].config(bg="chocolate", fg="white")

        self.AES_IV_Frame = Frame(main_body, pady=5, bg="brown")
        IV_Label = Label(self.AES_IV_Frame, text="IV:", fg="white", bg="brown")
        IV_Label.place(relx=0.05, rely=0.3)

        self.IV_Entry = Entry(self.AES_IV_Frame, width=self.winfo_width()*20)
        self.IV_Entry.place(relx=0.15, rely=0.3)

        self.IV_Generate = Button(self.AES_IV_Frame, text="Generate", bg="chocolate", fg="white", command=self.generate_AES_IV)
        self.IV_Generate.place(relx=0.75, rely=0.22)

        self.AES_Key_Frame = Frame(main_body, pady=5, bg="brown")
        Key_Label = Label(self.AES_Key_Frame, text="Key:", fg="white", bg="brown")
        Key_Label.place(relx=0.05, rely=0.3)

        self.AES_Key_Entry = Entry(self.AES_Key_Frame, width=self.winfo_width()*20)
        self.AES_Key_Entry.place(relx=0.16, rely=0.3)

        self.Key_Generate = Button(self.AES_Key_Frame, text="Generate", bg="chocolate", fg="white", command=self.generate_AES_Key)
        self.Key_Generate.place(relx=0.75, rely=0.22)

        # Diffie Hellman Stuff
        self.Diffie_prime1 = Entry(main_body)
        self.Prime1_label = Label(main_body, text="Prime Number 1: ", font=("Microsoft YaHei UI", 16), bg="#8f258f", fg="white")
        self.Diffie_prime2 = Entry(main_body)
        self.Prime2_label = Label(main_body, text="Prime Number 2: ", font=("Microsoft YaHei UI", 16), bg="#8f258f", fg="white")
        self.Diffie_secret1 = Entry(main_body)
        self.Secret1_label = Label(main_body, text="Secret Number 1: ", font=("Microsoft YaHei UI", 16), bg="#8f258f", fg="white")
        self.Diffie_secret2 = Entry(main_body)
        self.Secret2_label = Label(main_body, text="Secret Number 2: ", font=("Microsoft YaHei UI", 16), bg="#8f258f", fg="white")
        self.Diffie_Button = Button(main_body, text="Get Key", command=self.Diffie)
        self.Key1 = Label(main_body, text="Key 1:", font=("Montserrat", 24), bg="#8f258f", fg="white")
        self.Key2 = Label(main_body, text="Key 2:", font=("Montserrat", 24), bg="#8f258f", fg="white")

        # Vernam Stuff
        self.vernam_key = Text(self.special)

        self.special.bind("<Enter>", self.check)
        self.special.place(relx=0.7, rely=0.03, relwidth=0.2)

        # The frame that will act as a placeholder for the Entry widget for input
        self.input_frame = Frame(main_body, bg="white")
        self.input_label = Label(main_body, text="Input:", bg="#8f258f", fg="white", font=("Montserrat", "22"))
        self.input_label.place(relx=0.1, rely=0.28)
        self.input_frame.place(relx=0.265, rely=0.18, relwidth=0.635, relheight=0.3)
        
        self.button_encrypt = Button(main_body, text="Encrypt", command=self.encrypt)
        button_encrypt = self.button_encrypt
        button_encrypt.place(relx=0.38375, rely=0.505, relwidth=0.08, relheight=0.08)

        self.button_replace = Button(main_body, text="Replace", command=self.replace)
        button_replace = self.button_replace
        button_replace.place(relx=0.5425, rely=0.505, relwidth=0.08, relheight=0.08)

        self.button_decrypt = Button(main_body, text="Decrypt", command=self.decrypt)
        button_decrypt = self.button_decrypt
        button_decrypt.place(relx=0.70125, rely=0.505, relwidth=0.08, relheight=0.08)

        self.vernam_key_label = Label(main_body, text="Key:", bg="#8f258f", fg="white", font=("Montserrat", 22))

        self.input_entry = Text(self.input_frame, bg="white")
        self.input_entry.bind("<Enter>", self.check)
        self.input_entry.pack(fill=BOTH, expand=TRUE)

        self.output_frame = Frame(main_body, bg="white")
        self.output_label = Label(main_body, text="Output:", bg="#8f258f", fg="white", font=("Montserrat", "22"))
        self.output_label.place(relx=0.1, rely=0.73)
        self.output_frame.place(relx=0.265, rely=0.63, relwidth=0.635, relheight=0.3)
        
        self.output_text = Text(self.output_frame, bg="#ff8cff")
        self.output_text.pack(fill=BOTH, expand=TRUE)

    # Auto resize function, bounded to the canvas
    def resize(self, event):
        img = Image.open("images/background.png").resize(
            (event.width, event.height), Image.ANTIALIAS
        )
        self.img = ImageTk.PhotoImage(img)
        self.canvas.itemconfig(self.canvas_img, image=self.img)
        self.IV_Entry["width"] = self.winfo_width()//40
        self.AES_Key_Entry["width"] = self.winfo_width()//35

    def encrypt(self):
        self.output_text.delete(1.0, END)
        method = self.clicked.get()
        plain = self.input_entry.get("1.0", 'end-1c')
        if method == "Caesar Cipher":
            encrypted_text = MyCaesarCipher.encrypt(int(self.special_value.get()), plain)
            self.output_text.insert(1.0, encrypted_text)
        elif method == "Rail Fence Cipher":
            encrypted_text = MyRailFence.encrypt(int(self.special_value.get()), plain)
            self.output_text.insert(1.0, encrypted_text)
        elif method == "Simple Columnar Transposition":
            encrypted_text = MySimpleColumnarTransposition.encrypt(self.special_value.get(), plain)
            self.output_text.insert(1.0, encrypted_text)
        elif method == "Mono-alphabet Cipher":
            encrypted_text = MyMonoalphabetCipher.encrpyt(self.special_value.get(), plain)
            self.output_text.insert(1.0, encrypted_text)
        elif method == "Vernam Cipher":
            encrypted_text = MyVernamCipher.encrypt(self.vernam_key.get(1.0, "end-1c"), plain)
            self.output_text.insert(1.0, encrypted_text)
        elif method == "AES":
            mode = self.AES_Mode.get()
            keySize = self.Key_size.get()
            iv = self.IV_Entry.get()
            key = self.AES_Key_Entry.get()
            if mode == "CBC":
                encrypted_text = MyAes.CBC_encrypt(key, plain.encode("utf-8"), iv)
                self.output_text.insert(1.0, encrypted_text)
            elif mode == "CFB":
                encrypted_text = MyAes.CFB_encrypt(key, plain.encode("utf-8"), iv)
                self.output_text.insert(1.0, encrypted_text)
            elif mode == "OFB":
                encrypted_text = MyAes.OFB_encrypt(key, plain.encode("utf-8"), iv)
                self.output_text.insert(1.0, encrypted_text)
            elif mode == "ECB":
                encrypted_text = MyAes.ECB_encrypt(key, plain.encode("utf-8"))
                self.output_text.insert(1.0, encrypted_text)
        print(method)

    def decrypt(self):
        self.output_text.delete(1.0, END)
        method = self.clicked.get()
        plain = self.input_entry.get("1.0", 'end-1c')
        if method == "Caesar Cipher":
            decrypted_text = MyCaesarCipher.decrypt(int(self.special_value.get()), plain)
            self.output_text.insert(1.0, decrypted_text)
        elif method == "Rail Fence Cipher":
            decrypted_text = MyRailFence.decrypt(int(self.special_value.get()), plain)
            self.output_text.insert(1.0, decrypted_text)
        elif method == "Simple Columnar Transposition":
            decrypted_text = MySimpleColumnarTransposition.decrypt(self.special_value.get(), plain)
            print("SCT works")
            self.output_text.insert(1.0, decrypted_text)
        elif method == "Mono-alphabet Cipher":
            decrypted_text = MyMonoalphabetCipher.decrpyt(self.special_value.get(), plain)
            self.output_text.insert(1.0, decrypted_text)
        elif method == "Vernam Cipher":
            decrypted_text = MyVernamCipher.decrypt(self.special_value.get(), plain)
            self.output_text.insert(1.0, decrypted_text)
        elif method == "AES":
            mode = self.AES_Mode.get()
            keySize = self.Key_size.get()
            iv = self.IV_Entry.get()
            key = self.AES_Key_Entry.get()
            if mode == "CBC":
                decrypted_text = MyAes.CBC_decrypt(key, plain, iv).decode("utf-8")
                self.output_text.insert(1.0, decrypted_text)
            elif mode == "CFB":
                decrypted_text = MyAes.CFB_decrypt(key, plain, iv).decode("utf-8")
                self.output_text.insert(1.0, decrypted_text)
            elif mode == "OFB":
                decrypted_text = MyAes.OFB_decrypt(key, plain, iv).decode("utf-8")
                self.output_text.insert(1.0, decrypted_text)
            elif mode == "ECB":
                decrypted_text = MyAes.ECB_decrypt(key, plain).decode("utf-8")
                self.output_text.insert(1.0, decrypted_text)

    def replace(self):
        encrypted = self.output_text.get(1.0, "end-1c")
        self.output_text.delete(1.0, END)
        self.input_entry.delete(1.0, "end-1c")
        self.input_entry.insert(1.0, encrypted)

    def change_method(self, *args, **kwargs):
        method = self.clicked.get()
        self.AES_Key_Size_frame.place_forget()
        self.AES_Mode_Selection.pack_forget()
        self.AES_IV_Frame.place_forget()
        self.AES_Key_Frame.place_forget()
        self.special.place_forget()
        self.special_value.forget()
        self.input_frame.place_forget()
        self.input_label.place_forget()
        self.button_encrypt.place_forget()
        self.button_replace.place_forget()
        self.button_decrypt.place_forget()
        self.output_frame.place_forget()
        self.output_label.place_forget()
        self.vernam_key.pack_forget()
        self.vernam_key_label.place_forget()
        self.Prime1_label.place_forget()
        self.Diffie_prime1.place_forget()
        self.Prime2_label.place_forget()
        self.Diffie_prime2.place_forget()
        self.Secret1_label.place_forget()
        self.Diffie_secret1.place_forget()
        self.Secret2_label.place_forget()
        self.Diffie_secret2.place_forget()
        self.Key1.place_forget()
        self.Key2.place_forget()
        self.Diffie_Button.place_forget()
        self.description.pack()
        self.special["bg"] = "indian red"
        if method != "AES" and method != "Diffie Hellman" and method!= "Vernam Cipher":
            self.special.place(relx=0.7, rely=0.03, relwidth=0.2)
            self.special_value.pack()
            self.input_frame.place(relx=0.265, rely=0.18, relwidth=0.635, relheight=0.3)
            self.input_label.place(relx=0.1, rely=0.28)
            self.button_encrypt.place(relx=0.38375, rely=0.505, relwidth=0.08, relheight=0.08)
            self.button_replace.place(relx=0.5425, rely=0.505, relwidth=0.08, relheight=0.08)
            self.button_decrypt.place(relx=0.70125, rely=0.505, relwidth=0.08, relheight=0.08)
            self.output_label.place(relx=0.1, rely=0.73)
            self.output_frame.place(relx=0.265, rely=0.63, relwidth=0.635, relheight=0.3)

            if method == "Caesar Cipher":
                self.description["text"] = "Shift Key(digits):"
            elif method == "Rail Fence Cipher":
                self.description["text"] = "Rows(digits):"
            elif method == "Simple Columnar Transposition" or method == "Mono-alphabet Cipher":
                self.description["text"] = "Key:"
        elif method == "Vernam Cipher":
            self.description.pack_forget()
            self.vernam_key_label.place(relx=0.1, rely=0.2)
            self.special.place(relx=0.265, rely=0.175, relwidth=0.635, relheight=0.15)
            self.special["bg"] = "#8f258f"
            self.input_frame.place(relx=0.265, rely=0.33, relwidth=0.635, relheight=0.2)
            self.input_label.place(relx=0.1, rely=0.38)
            self.output_frame.place(relx=0.265, rely=0.68, relwidth=0.635, relheight=0.2)
            self.output_label.place(relx=0.1, rely=0.73)
            self.button_encrypt.place(relx=0.38375, rely=0.565, relwidth=0.08, relheight=0.08)
            self.button_replace.place(relx=0.5425, rely=0.565, relwidth=0.08, relheight=0.08)
            self.button_decrypt.place(relx=0.70125, rely=0.565, relwidth=0.08, relheight=0.08)
            self.vernam_key.pack(fill=BOTH, expand=True)

        elif method == "AES":
            self.description["text"] = "Method:"
            self.special.place(relx=0.7, rely=0.03, relwidth=0.2)
            self.AES_Mode_Selection.pack()
            self.AES_Key_Size_frame.place(relx=0.5, rely=0.03, relwidth=0.15)
            self.input_frame.place(relx=0.265, rely=0.33, relwidth=0.635, relheight=0.2)
            self.input_label.place(relx=0.1, rely=0.38)
            self.output_frame.place(relx=0.265, rely=0.68, relwidth=0.635, relheight=0.2)
            self.output_label.place(relx=0.1, rely=0.73)
            self.button_encrypt.place(relx=0.38375, rely=0.565, relwidth=0.08, relheight=0.08)
            self.button_replace.place(relx=0.5425, rely=0.565, relwidth=0.08, relheight=0.08)
            self.button_decrypt.place(relx=0.70125, rely=0.565, relwidth=0.08, relheight=0.08)
            self.AES_IV_Frame.place(relx=0.1, rely=0.2, relwidth=0.35, relheight=0.08)
            if self.AES_Mode.get() == "ECB":
                self.AES_IV_Frame.place_forget()
            self.AES_Key_Frame.place(relx=0.5, rely=0.2, relwidth=0.4, relheight=0.08)
        else:
            self.Prime1_label.place(relx=0.27, rely=0.187)
            self.Diffie_prime1.place(relx=0.53, rely=0.2)
            self.Prime2_label.place(relx=0.27, rely=0.287)
            self.Diffie_prime2.place(relx=0.53, rely=0.3)
            self.Secret1_label.place(relx=0.27, rely=0.387)
            self.Diffie_secret1.place(relx=0.53, rely=0.4)
            self.Secret2_label.place(relx=0.27, rely=0.487)
            self.Diffie_secret2.place(relx=0.53, rely=0.5)
            self.Diffie_Button.place(relx=0.47, rely=0.6)

    def generate_AES_Key(self):
        self.AES_Key_Entry.delete(0, END)
        keySize = self.Key_size.get()
        key = MyAes.get_random_alphanumeric(int(keySize)/8)
        self.AES_Key_Entry.insert(0, key)

    def generate_AES_IV(self):
        self.IV_Entry.delete(0, END)
        iv = MyAes.get_random_alphanumeric(16)
        self.IV_Entry.insert(0, iv)

    def check(self, *args, **kwargs):
        method = self.clicked.get()
        data = self.input_entry.get(1.0, END)
        if method != "AES" and method != "Diffie Hellman" and method != "Vernam Cipher":
            value = self.special_value.get()
            if value == "" or data == "":
                self.button_encrypt["state"] = "disabled"
                self.button_decrypt["state"] = "disabled"
            else:
                self.button_encrypt["state"] = "normal"
                self.button_decrypt["state"] = "normal"
        elif method == "AES":
            iv = self.IV_Entry.get()
            key = self.AES_Key_Entry.get()
            mode = self.AES_Mode
            if mode != "ECB":
                if iv == "" or data == "" or key == "":
                    self.button_encrypt["state"] = "disabled"
                    self.button_decrypt["state"] = "disabled"
                else:
                    self.button_encrypt["state"] = "normal"
                    self.button_decrypt["state"] = "normal"
            else:
                if data == "" or key == "":
                    self.button_encrypt["state"] = "disabled"
                    self.button_decrypt["state"] = "disabled"
                else:
                    self.button_encrypt["state"] = "normal"
                    self.button_decrypt["state"] = "normal"
        elif method == "Vernam Cipher":
            key = self.vernam_key.get(1.0, END)
            if data == "" or key == "":
                self.button_encrypt["state"] = "disabled"
                self.button_decrypt["state"] = "disabled"
            else:
                self.button_encrypt["state"] = "normal"
                self.button_decrypt["state"] = "normal"


    def Diffie(self):
        self.Key1.place_forget()
        self.Key2.place_forget()
        n = int(self.Diffie_prime1.get())
        g = int(self.Diffie_prime2.get())
        x = int(self.Diffie_secret1.get())
        y = int(self.Diffie_secret2.get())
        keys = MyDiffieHellman.get_keys(n, g, x, y)
        self.Key1["text"] = "Key 1: " + str(keys[0])
        self.Key2["text"] = "Key 2: " + str(keys[1])
        self.Key1.place(relx=0.2, rely=0.8)
        self.Key2.place(relx=0.7, rely=0.8)

    def to_algorithms(self):
        self.home_page.place_forget()
        self.main_body.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)

    def to_lesson(self):
        self.home_page.place_forget()
        self.lesson_body.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)

    def change_to_affordability(self):
        self.button_title["text"] = "Affordability"
        self.title_definition["text"] = "Cost and Effort in Implementation"
        self.explanation["text"] = "The security policy should not be too costly and \nincur too much effort to implement"

    def change_to_functionality(self):
        self.button_title["text"] = "Functionality"
        self.title_definition["text"] = "Mechanism of providing security"
        self.explanation["text"] = "There should be available security mechanism \nto support the security policy"

    def change_to_cultural_issues(self):
        self.button_title["text"] = "Cultural Issues"
        self.title_definition["text"] = "Whether the policy gels with people's expectations."
        self.explanation["text"] = "The security policy should gel with people’s \nexpectations, working style and beliefs\n" \
                                   "e.g in the use of email, WhatsApp and Facebook at work"

    def change_to_legality(self):
        self.button_title["text"] = "Legality"
        self.title_definition["text"] = "Whether the policy meets legal requirements"
        self.explanation["text"] = "The policy should meet legal requirements. \ne.g. use of 2FA in Internet banking."

    def quiz(self):
        self.quiz_score = 0
        self.lesson_body.place_forget()
        self.quiz_body.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)
        self.quiz_question1()
        self.next_question["command"] = self.quiz_question2

    def quiz_question1(self):
        self.quiz_question["text"] = "Q1. Which of the following is not a characteristic\nof a good Security Policy?"
        self.option1_button["text"] = "Functionality"
        self.option1_button["command"] = self.quiz1_wrong
        self.option2_button["text"] = "Legality"
        self.option2_button["command"] = self.quiz1_wrong
        self.option3_button["text"] = "Authenticity"
        self.option3_button["command"] = self.quiz1_correct
        self.option4_button["text"] = "Cultural Issues"
        self.option4_button["command"] = self.quiz1_wrong

    def quiz1_correct(self):
        self.option1_button["bg"] = "red"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "green"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "red"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "Correct!"
        self.quiz_score += 1
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz1_wrong(self):
        self.option1_button["bg"] = "red"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "green"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "red"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "That wasn't right"
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz_question2(self):
        self.quiz_reset()
        self.quiz_question["text"] = "Q2. Which characteristic refers to\n'Mechanism of providing Security'?"
        self.option1_button["text"] = "Functionality"
        self.option1_button["command"] = self.quiz2_correct
        self.option2_button["text"] = "Cultural Issues"
        self.option2_button["command"] = self.quiz2_wrong
        self.option3_button["text"] = "Affordability"
        self.option3_button["command"] = self.quiz2_wrong
        self.option4_button["text"] = "Legality"
        self.option4_button["command"] = self.quiz2_wrong

    def quiz2_correct(self):
        self.option1_button["bg"] = "green"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "red"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "red"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "Correct!"
        self.quiz_score += 1
        self.next_question["command"] = self.quiz_question3
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz2_wrong(self):
        self.option1_button["bg"] = "green"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "red"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "red"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "That wasn't right"
        self.next_question["command"] = self.quiz_question3
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz_question3(self):
        self.quiz_reset()
        self.quiz_question["text"] = "Q3. Which of the following is not a part\nof successful implementation of Security Policy?"
        self.option1_button["text"] = "Use Simple Language"
        self.option1_button["command"] = self.quiz3_wrong
        self.option2_button["text"] = "Establish Accountability"
        self.option2_button["command"] = self.quiz3_wrong
        self.option3_button["text"] = "Outline everybody's responsibilities"
        self.option3_button["command"] = self.quiz3_wrong
        self.option4_button["text"] = "Legality"
        self.option4_button["command"] = self.quiz3_correct

    def quiz3_correct(self):
        self.option1_button["bg"] = "red"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "red"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "green"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "Correct!"
        self.quiz_score += 1
        self.next_question["command"] = self.quiz_results
        self.next_question["text"] = "View results"
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz3_wrong(self):
        self.option1_button["bg"] = "red"
        self.option1_button["fg"] = "white"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "ridge"
        self.option2_button["bg"] = "red"
        self.option2_button["fg"] = "white"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "ridge"
        self.option3_button["bg"] = "red"
        self.option3_button["fg"] = "white"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "ridge"
        self.option4_button["bg"] = "green"
        self.option4_button["fg"] = "white"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "ridge"
        self.feedback["text"] = "That wasn't right"
        self.next_question["command"] = self.quiz_results
        self.next_question["text"] = "View results"
        self.feedback.place(relx=0.35, rely=0.7, relwidth=0.3)
        self.next_question.place(relx=0.4, rely=0.75, relwidth=0.2)

    def quiz_reset(self):
        self.option1_button["bg"] = "SystemButtonFace"
        self.option1_button["fg"] = "black"
        self.option1_button["command"] = ""
        self.option1_button["relief"] = "raised"
        self.option2_button["bg"] = "SystemButtonFace"
        self.option2_button["fg"] = "black"
        self.option2_button["command"] = ""
        self.option2_button["relief"] = "raised"
        self.option3_button["bg"] = "SystemButtonFace"
        self.option3_button["fg"] = "black"
        self.option3_button["command"] = ""
        self.option3_button["relief"] = "raised"
        self.option4_button["bg"] = "SystemButtonFace"
        self.option4_button["fg"] = "black"
        self.option4_button["command"] = ""
        self.option4_button["relief"] = "raised"
        self.feedback["text"] = ""
        self.next_question["text"] = "Next"
        self.feedback.place_forget()
        self.next_question.place_forget()

    def quiz_results(self):
        self.quiz_reset()
        self.quiz_body.place_forget()
        self.results_body.place(relx=0.3, rely=0.25, relwidth=0.4, relheight=0.45)
        self.result = "Results: " + str(self.quiz_score) + "/3"
        results_label = Label(self.results_body, text=self.result, bg="#8f258f", fg="white", font=("Montserrat", 18))
        if self.quiz_score == 0:
            self.remark = "Better luck next time :("
        elif self.quiz_score == 1:
            self.remark = "Good try"
        elif self.quiz_score == 2:
            self.remark = "Well done"
        elif self.quiz_score == 3:
            self.remark = "Excellent!"
        results_label.place(relx=0.1, rely=0.03, relwidth=0.8)
        remarks = Label(self.results_body, text=self.remark, bg="#8f258f", fg="white", font=("Monstserrat", 14))
        remarks.place(relx=0.1, rely=0.3, relwidth=0.8)

    def lesson_to_home(self):
        self.lesson_body.place_forget()
        self.home_page.place(relx=0.3, rely=0.25, relwidth=0.4, relheight=0.45)

    def quiz_to_home(self):
        self.results_body.place_forget()
        self.home_page.place(relx=0.3, rely=0.25, relwidth=0.4, relheight=0.45)

    def quiz_to_lesson(self):
        self.results_body.place_forget()
        self.lesson_body.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)

    def quiz_to_algorithms(self):
        self.results_body.place_forget()
        self.main_body.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)

    def algorithms_to_home(self):
        self.main_body.place_forget()
        self.home_page.place(relx=0.3, rely=0.25, relwidth=0.4, relheight=0.45)


app = Root()
app.mainloop()
