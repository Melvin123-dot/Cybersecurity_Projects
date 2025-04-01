# gui.py
import tkinter as tk
from tkinter import scrolledtext
from CyberOps import CyberSecurityChatbot

class ChatbotGUI:
    def __init__(self):
        self.bot = CyberSecurityChatbot()
        self.create_gui()

    def create_gui(self):
        """ Set up the GUI for the chatbot. """
        self.window = tk.Tk()
        self.window.title("CyberSecurity Chatbot")

        self.chat_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(padx=10, pady=10, expand=True, fill='both')

        self.entry_frame = tk.Frame(self.window)
        self.entry_frame.pack(padx=10, pady=10, fill='x')

        self.entry_field = tk.Entry(self.entry_frame, font=('Arial', 14))
        self.entry_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.entry_field.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start the chat
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, "Welcome to CyberOps Chatbot! I'm here to help you with your queries related to cybersecurity, various hacking tools used by hackers,"
          " tips for maintaining a secure system, and privacy information.\n")
        self.chat_area.config(state='disabled')

        self.window.mainloop()

    def send_message(self, event=None):
        """ Handle sending the user message and receiving a response. """
        user_input = self.entry_field.get().strip().lower()
        if user_input in ["Thanks", "Thank You"]:
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, "ChatBot: Thank you for using the Cybersecurity Chatbot. Stay safe!\n")
            self.chat_area.config(state='disabled')
            self.window.after(1000, self.on_close)
            return
        
        response = self.bot.generate_response(user_input)
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"User: {user_input}\n")
        self.chat_area.insert(tk.END, f"ChatBot: {response}\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)  # Scroll to the end

        self.entry_field.delete(0, tk.END)  # Clear the entry field

    def on_close(self):
        """ Handle window close event. """
        self.window.destroy()

# Usage
if __name__ == "__main__":
    ChatbotGUI()
