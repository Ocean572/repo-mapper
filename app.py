import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk

EXCLUDED_DIRS = {'.git', '__pycache__', 'node_modules'}

class FolderStructureMapper(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder Structure Mapper")
        self.geometry("950x800")
        self.folder_path = ""
        self.selected_files = set()

        # FIX: Apply a custom style to the Treeview to ensure consistent rendering
        style = ttk.Style(self)
        # Use a monospaced font and set a row height to prevent text from overlapping
        style.configure("Treeview", font=("monospace", 10), rowheight=25)

        # Select folder button
        self.select_button = tk.Button(self, text="Select Folder", command=self.select_folder)
        self.select_button.pack(pady=10)

        # File/folder treeview
        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        self.tree = ttk.Treeview(self.tree_frame, show="tree", selectmode="none")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Attach vertical scrollbar to the treeview
        self.tree_scroll = tk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.tree_scroll.set)

        # For checkboxes: store check states
        self.check_vars = {}

        # Submit button
        self.submit_button = tk.Button(self, text="Submit Selection", command=self.submit_selection)
        self.submit_button.pack(pady=10)

        # Output display
        self.output_label = tk.Label(self, text="Generated Output:")
        self.output_label.pack()

        self.output_box = scrolledtext.ScrolledText(self, height=20, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(fill='both', padx=10, pady=(0, 5))
        self.output_box.config(state='disabled')

        # Copy button
        self.copy_button = tk.Button(self, text="Copy to Clipboard", command=self.copy_output)
        self.copy_button.pack(pady=(0, 10))

        # FIX: Bind single-click for selection and double-click for folder expansion
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Double-1>", self.on_tree_double_click)

    def is_virtualenv(self, dir_path):
        return (
            os.path.isfile(os.path.join(dir_path, 'pyvenv.cfg')) or
            os.path.exists(os.path.join(dir_path, 'bin', 'activate')) or
            os.path.exists(os.path.join(dir_path, 'Scripts', 'activate.bat'))
        )

    def select_folder(self):
        folder_path = filedialog.askdirectory(title="Select a Folder to Map")
        if folder_path:
            self.folder_path = os.path.abspath(folder_path)
            self.selected_files.clear()
            for widget in self.tree.get_children():
                self.tree.delete(widget)
            self.check_vars.clear()
            # Add the root directory name to the tree first
            root_node = self.tree.insert("", "end", text=os.path.basename(self.folder_path) + "/", open=True)
            self.populate_tree(self.folder_path, root_node)


    def populate_tree(self, path, parent):
        """Recursively add nodes to treeview."""
        try:
            entries = sorted(os.listdir(path), key=lambda x: (os.path.isfile(os.path.join(path, x)), x.lower()))
        except PermissionError:
            return
        for entry in entries:
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                if entry.lower() in EXCLUDED_DIRS or self.is_virtualenv(full_path):
                    continue
                node = self.tree.insert(parent, "end", text=entry + "/", open=False)
                self.populate_tree(full_path, node)
            else:
                rel_path = os.path.relpath(full_path, self.folder_path)
                # FIX: Add an unchecked box symbol at the beginning
                node = self.tree.insert(parent, "end", text="☐ " + entry)
                self.check_vars[node] = tk.BooleanVar(value=False)
                self.tree.set(node, 'fullpath', rel_path)

    def on_tree_double_click(self, event):
        """Handle double-clicks to expand/collapse folders."""
        item = self.tree.identify_row(event.y)
        # Check if the item is a directory (it won't be in check_vars)
        if item and item not in self.check_vars:
            is_open = self.tree.item(item, "open")
            self.tree.item(item, open=not is_open)

    def on_tree_click(self, event):
        """Toggle checkbox on single click (files only)."""
        item = self.tree.identify_row(event.y)
        region = self.tree.identify_region(event.x, event.y)

        # Only toggle if the click is on a file's text/icon area
        if item and region == "tree" and item in self.check_vars:
            checked = self.check_vars[item].get()
            self.check_vars[item].set(not checked)
            rel_path = self.tree.set(item, 'fullpath')
            
            if not checked:
                self.selected_files.add(rel_path)
            else:
                self.selected_files.discard(rel_path)
            
            self.update_tree_checkbox(item)

    def update_tree_checkbox(self, item):
        """Visually update the checkbox in the item's label."""
        checked = self.check_vars[item].get()
        current_text = self.tree.item(item, "text")
        # Strip any existing checkbox to get the base filename
        base_text = current_text.lstrip("☐ ☑ ")
        
        if checked:
            self.tree.item(item, text=f"☑ {base_text}")
        else:
            self.tree.item(item, text=f"☐ {base_text}")

    def get_directory_tree_string(self, folder_path):
        """Generate a string representing the directory tree like `tree`."""
        tree_lines = []
        
        def recurse(path, prefix=""):
            try:
                # Get and sort entries, directories first
                entries = sorted(os.listdir(path), key=lambda x: (os.path.isdir(os.path.join(path, x)), x.lower()))
            except PermissionError:
                return
            
            # Find the last entry to use the correct connector
            pointers = ["├── "] * (len(entries) - 1) + ["└── "]

            for pointer, entry in zip(pointers, entries):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    if entry.lower() in EXCLUDED_DIRS or self.is_virtualenv(full_path):
                        continue
                    tree_lines.append(f"{prefix}{pointer}{entry}/")
                    extension = "│   " if pointer == "├── " else "    "
                    recurse(full_path, prefix + extension)
                else:
                    tree_lines.append(f"{prefix}{pointer}{entry}")

        tree_lines.append(os.path.basename(folder_path) + "/")
        recurse(folder_path)
        return "\n".join(tree_lines)

    def submit_selection(self):
        if not self.folder_path:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return

        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select at least one file to include in the output.")
            return

        dir_tree = self.get_directory_tree_string(self.folder_path)
        final_output = [f"Directory tree:\n{dir_tree}\n\nSelected files for context from '{os.path.basename(self.folder_path)}':\n"]

        for rel_path in sorted(self.selected_files):
            abs_path = os.path.join(self.folder_path, rel_path)
            if os.path.isfile(abs_path):
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    header = f"--- {rel_path} ---\n"
                    final_output.append(f"{header}{code.strip()}\n")
                except Exception as e:
                    final_output.append(f"--- ERROR reading {rel_path}: {e} ---\n")

        output_text = "\n".join(final_output).strip()
        self.output_box.config(state='normal')
        self.output_box.delete("1.0", tk.END)
        self.output_box.insert(tk.END, output_text)
        self.output_box.config(state='disabled')

    def copy_output(self):
        text = self.output_box.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            messagebox.showinfo("Copied", "Output copied to clipboard.")
        else:
            messagebox.showwarning("Empty", "No output to copy.")

if __name__ == "__main__":
    app = FolderStructureMapper()
    # Configure a hidden column to store the full path of files
    app.tree["columns"] = ("fullpath",)
    app.tree.column("fullpath", width=0, stretch=False)
    app.mainloop()