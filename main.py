import base64
import tkinter as tk
from tkinter import filedialog, messagebox


def encode():
    input_file = filedialog.askopenfilename(title="Select Input File")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Select Output File", defaultextension=".txt")
    if not output_file:
        return

    try:
        with open(input_file, "rb") as f:
            input_data = f.read()
            hash_int = int.from_bytes(hash(input_data), byteorder='big')
            encoded_code = base64.b64encode(hash_int.to_bytes(16, byteorder='big'))[:20].decode()

        with open(output_file, "w") as f:
            f.write(encoded_code)

        messagebox.showinfo("Success", "File has been encoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def decode():
    input_file = filedialog.askopenfilename(title="Select Encoded File")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Select Output File", defaultextension=".txt")
    if not output_file:
        return

    try:
        with open(input_file, "r") as f:
            encoded_code = f.read()

        # Convert encoded code to byte-like object and decode
        hash_bytes = base64.b64decode(encoded_code.encode())
        input_data = hash_bytes[:-16]
        expected_hash = int.from_bytes(hash_bytes[-16:], byteorder='big')

        # Verify hash of input data
        actual_hash = int.from_bytes(hash(input_data), byteorder='big')
        if actual_hash != expected_hash:
            raise ValueError("Hash mismatch: Input file may have been tampered with")

        with open(output_file, "wb") as f:
            f.write(input_data)

        messagebox.showinfo("Success", "File has been decoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def create_gui():
    root = tk.Tk()
    root.title("Document Encoder and Decoder")

    tk.Label(root, text="Select a file to encode or decode:").grid(row=0, column=0, padx=10, pady=10)

    encode_btn = tk.Button(root, text="Encode", width=20, command=encode)
    encode_btn.grid(row=1, column=0, padx=10, pady=10)

    decode_btn = tk.Button(root, text="Decode", width=20, command=decode)
    decode_btn.grid(row=1, column=1, padx=10, pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
