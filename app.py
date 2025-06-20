import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from tkinter import font as tkfont # <-- IMPORT ADDED HERE

# --- MODEL ---
EXCLUDED_DIRS = {'.git', '__pycache__', 'node_modules'}

class FileManager:
    """Handles file system logic, independent of the GUI."""
    def __init__(self, excluded_dirs):
        self.excluded_dirs = excluded_dirs

    def is_virtualenv(self, dir_path):
        """Checks if a directory is a Python virtual environment."""
        return (
            os.path.isfile(os.path.join(dir_path, 'pyvenv.cfg')) or
            os.path.exists(os.path.join(dir_path, 'bin', 'activate')) or
            os.path.exists(os.path.join(dir_path, 'Scripts', 'activate.bat'))
        )

    def get_directory_tree_string(self, folder_path):
        """Generates a string representing the directory tree like the `tree` command."""
        tree_lines = []
        
        def recurse(path, prefix=""):
            try:
                entries = [e for e in os.listdir(path) if not (os.path.isdir(os.path.join(path, e)) and (e in self.excluded_dirs or self.is_virtualenv(os.path.join(path, e))))]
                entries.sort(key=lambda x: (os.path.isfile(os.path.join(path, x)), x.lower()))
            except PermissionError:
                return

            pointers = ["├── "] * (len(entries) - 1) + ["└── "]
            for pointer, entry in zip(pointers, entries):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    tree_lines.append(f"{prefix}{pointer}{entry}/")
                    extension = "│   " if pointer == "├── " else "    "
                    recurse(full_path, prefix + extension)
                else:
                    tree_lines.append(f"{prefix}{pointer}{entry}")

        tree_lines.append(os.path.basename(folder_path) + "/")
        recurse(folder_path)
        return "\n".join(tree_lines)


# --- VIEW ---
class AppView(tk.Tk):
    """Manages the user interface, widgets, and styling."""
    def __init__(self, title, geometry):
        super().__init__()
        self.title(title)
        self.geometry(geometry)
        
        self.configure_styles()

        self.selected_files = set()
        self.check_vars = {}
        self.folder_path = ""

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.select_button = ttk.Button(top_frame, text="Select Folder")
        self.select_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.submit_button = ttk.Button(top_frame, text="Generate Output")
        self.submit_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))

        tree_container = ttk.Frame(main_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tree_container, show="tree", selectmode="none")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.tree["columns"] = ("fullpath",)
        self.tree.column("fullpath", width=0, stretch=False)

        tree_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.output_label = ttk.Label(output_frame, text="Generated Output:")
        self.output_label.pack(anchor="w")

        self.output_box = scrolledtext.ScrolledText(output_frame, height=15, wrap=tk.WORD, font=("Courier New", 11), relief=tk.SOLID, borderwidth=1)
        self.output_box.pack(fill='both', expand=True, pady=(5, 10))
        self.output_box.config(state='disabled', bg="#2b2b2b", fg="#a9b7c6")

        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X)
        
        self.copy_button = ttk.Button(bottom_frame, text="Copy to Clipboard")
        self.copy_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

    def configure_styles(self):
        """Sets up the visual style for the application."""
        style = ttk.Style(self)
        style.theme_use('clam')

        BG_COLOR = "#3c3f41"
        FG_COLOR = "#f0f0f0"
        SELECT_BG = "#4a6984"
        
        self.configure(bg=BG_COLOR)
        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=("TkDefaultFont", 11))
        
        # Define the font we want to use in the Treeview
        tree_font = tkfont.Font(family="TkDefaultFont", size=12)
        
        # Get the required height for a line of text in this font and add padding
        row_height = tree_font.metrics("linespace") + 5 

        # Use the calculated font and rowheight in the style
        style.configure("Treeview", 
                        font=tree_font, 
                        rowheight=row_height,
                        background="#2b2b2b",
                        fieldbackground="#2b2b2b",
                        foreground="#a9b7c6")
        
        style.map("Treeview", background=[('selected', SELECT_BG)])

        style.configure("TButton", padding=6, relief="flat", background="#555555", foreground=FG_COLOR)
        style.map("TButton", background=[('active', '#666666')], foreground=[('active', FG_COLOR)])
        
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TFrame", background=BG_COLOR)


# --- CONTROLLER ---
class Controller:
    """Handles user input and coordinates the View and Model."""
    def __init__(self, model, view):
        self.model = model
        self.view = view
        self.bind_events()

    def bind_events(self):
        """Binds widget events to controller methods."""
        self.view.select_button.config(command=self.select_folder)
        self.view.submit_button.config(command=self.submit_selection)
        self.view.copy_button.config(command=self.copy_output)
        self.view.tree.bind("<Button-1>", self.on_tree_click)
        
        self.view.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Gracefully closes the application."""
        self.view.destroy()

    def select_folder(self):
        """Opens a dialog to select a folder and populates the tree."""
        folder_path = filedialog.askdirectory(title="Select a Folder to Map")
        if not folder_path:
            return

        self.view.folder_path = os.path.abspath(folder_path)
        self.view.selected_files.clear()
        self.view.check_vars.clear()

        for item in self.view.tree.get_children():
            self.view.tree.delete(item)

        root_name = os.path.basename(self.view.folder_path)
        root_node = self.view.tree.insert("", "end", text=f"📁 {root_name}/", open=True)
        self.populate_tree(self.view.folder_path, root_node)

    def populate_tree(self, path, parent):
        """Recursively populates the treeview, skipping excluded directories."""
        try:
            entries = sorted(os.listdir(path), key=lambda x: (os.path.isfile(os.path.join(path, x)), x.lower()))
        except PermissionError:
            return
        
        for entry in entries:
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                if entry in self.model.excluded_dirs or self.model.is_virtualenv(full_path):
                    continue
                node = self.view.tree.insert(parent, "end", text=f"📁 {entry}/", open=False)
                self.populate_tree(full_path, node)
            else:
                rel_path = os.path.relpath(full_path, self.view.folder_path)
                node = self.view.tree.insert(parent, "end", text=f"☐ {entry}")
                self.view.check_vars[node] = tk.BooleanVar(value=False)
                self.view.tree.set(node, 'fullpath', rel_path)

    def on_tree_click(self, event):
        """Handles single-clicks on the tree."""
        item_id = self.view.tree.identify_row(event.y)
        region = self.view.tree.identify_region(event.x, event.y)

        if not item_id or region != "tree":
            return
            
        if item_id in self.view.check_vars:
            checked = self.view.check_vars[item_id].get()
            self.view.check_vars[item_id].set(not checked)
            rel_path = self.view.tree.set(item_id, 'fullpath')
            
            if not checked:
                self.view.selected_files.add(rel_path)
            else:
                self.view.selected_files.discard(rel_path)
            
            self.update_tree_checkbox(item_id)
        
        else:
            is_open = self.view.tree.item(item_id, "open")
            self.view.tree.item(item_id, open=not is_open)

    def update_tree_checkbox(self, item):
        """Visually updates the checkbox in the item's label."""
        checked = self.view.check_vars[item].get()
        current_text = self.view.tree.item(item, "text")
        base_text = current_text.lstrip("☐ ☑ ")
        
        new_text = f"☑ {base_text}" if checked else f"☐ {base_text}"
        self.view.tree.item(item, text=new_text)

    def submit_selection(self):
        """Generates the final output string and displays it."""
        if not self.view.folder_path:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return

        if not self.view.selected_files:
            messagebox.showwarning("No Files", "Please select at least one file.")
            return

        dir_tree = self.model.get_directory_tree_string(self.view.folder_path)
        final_output = [f"Directory tree for '{os.path.basename(self.view.folder_path)}':\n\n{dir_tree}\n\n--- Selected File Contents ---\n"]

        for rel_path in sorted(self.view.selected_files):
            abs_path = os.path.join(self.view.folder_path, rel_path)
            if os.path.isfile(abs_path):
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    header = f"\n--- File: {rel_path} ---\n"
                    final_output.append(f"{header}{code.strip()}\n")
                except Exception as e:
                    final_output.append(f"\n--- ERROR reading {rel_path}: {e} ---\n")

        output_text = "\n".join(final_output).strip()
        self.view.output_box.config(state='normal')
        self.view.output_box.delete("1.0", tk.END)
        self.view.output_box.insert(tk.END, output_text)
        self.view.output_box.config(state='disabled')

    def copy_output(self):
        """Copies the generated output to the clipboard."""
        text = self.view.output_box.get("1.0", tk.END).strip()
        if text:
            self.view.clipboard_clear()
            self.view.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied to clipboard.", parent=self.view)
        else:
            messagebox.showwarning("Empty", "No output to copy.", parent=self.view)


if __name__ == "__main__":
    file_manager = FileManager(excluded_dirs=EXCLUDED_DIRS)
    app_view = AppView(title="Folder Structure Mapper", geometry="1000x850")
    controller = Controller(model=file_manager, view=app_view)
    app_view.mainloop()