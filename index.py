import tkinter as tk
import subprocess

def symmetric_clicked():
    subprocess.Popen(["python", "symmetric.py"])

def asymmetric_clicked():
    subprocess.Popen(["python", "asymmetric.py"])

# Create the main window
root = tk.Tk()
root.title("Select Method")
root.config(bg='lightblue')

# Create a label
label = tk.Label(root, text="Select Method", font=('Helvetica', 18), bg='lightblue', fg='white')
label.pack(pady=20)

# Create buttons
symmetric_button = tk.Button(root, text="Symmetric", command=symmetric_clicked, bg='white', font=('Helvetica', 14))
symmetric_button.pack(pady=10)

asymmetric_button = tk.Button(root, text="Asymmetric", command=asymmetric_clicked, bg='white', font=('Helvetica', 14))
asymmetric_button.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()