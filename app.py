import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
from auth import hash_password, verify_password
from crypto import get_encryption_key, encrypt_data, decrypt_data
import sqlite3
import os

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass 🔒")
        self.root.geometry("600x450")
        
        # Initialize database FIRST
        self.initialize_database()
        
        # Then configure styles
        self.setup_styles()
        
        # Security setup
        self.encryption_key = get_encryption_key()
        self.master_password_hash = self.load_master_password()
        
        # UI Setup
        if not self.master_password_hash:
            self.show_setup_ui()
        else:
            self.show_login_ui()

    def initialize_database(self):
        """Ensure all tables exist before any operations"""
        conn = sqlite3.connect("vault.db")
        try:
            # Master password table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    hash TEXT PRIMARY KEY
                )
            """)
            
            # Passwords table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    website TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def setup_styles(self):
        """Configure modern dark theme"""
        style = ttk.Style()
        style.theme_use("clam")
        
        # Color scheme
        bg = "#2d2d2d"
        fg = "#ffffff"
        accent = "#4fc3f7"
        entry_bg = "#3d3d3d"
        
        # General styling
        style.configure(".", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, insertcolor=fg)
        style.configure("TButton", background="#3d3d3d", foreground=fg, borderwidth=0)
        style.map("TButton", background=[("active", "#4d4d4d")])
        
        # Custom styles
        style.configure("Accent.TButton", background=accent, foreground="#000000", font=("Segoe UI", 10, "bold"))
        style.configure("Danger.TButton", background="#f44336", foreground="#ffffff")
        style.configure("Treeview", background=entry_bg, foreground=fg, fieldbackground=entry_bg)
        style.configure("Treeview.Heading", background="#3d3d3d", foreground=accent, font=("Segoe UI", 9, "bold"))
        
        self.root.configure(bg=bg)

    # ================= SECURITY METHODS =================
    def load_master_password(self):
        """Load master password hash from database"""
        conn = self.get_db_connection()
        try:
            result = conn.execute("SELECT hash FROM master_password LIMIT 1").fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def save_master_password(self, password):
        """Store master password hash in database"""
        conn = self.get_db_connection()
        try:
            conn.execute("DELETE FROM master_password")
            conn.execute("INSERT INTO master_password (hash) VALUES (?)", 
                        (hash_password(password),))
            conn.commit()
        finally:
            conn.close()

    def get_db_connection(self):
        """Create secure database connection"""
        return sqlite3.connect("vault.db")

    # ================= UI METHODS =================
    def show_setup_ui(self):
        """First-time password setup UI"""
        self.clear_ui()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Set Master Password:", font=("Segoe UI", 12, "bold")).pack(pady=10)
        self.pwd_entry = ttk.Entry(frame, show="*", font=("Segoe UI", 10))
        self.pwd_entry.pack(pady=10, ipady=5, fill="x")
        
        ttk.Button(
            frame,
            text="Set Password",
            command=self.handle_first_time_setup,
            style="Accent.TButton"
        ).pack(pady=15, ipady=5, fill="x")

    def show_login_ui(self):
        """Login UI"""
        self.clear_ui()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Enter Master Password:", font=("Segoe UI", 12, "bold")).pack(pady=10)
        self.pwd_entry = ttk.Entry(frame, show="*", font=("Segoe UI", 10))
        self.pwd_entry.pack(pady=10, ipady=5, fill="x")
        
        ttk.Button(
            frame,
            text="Unlock Vault",
            command=self.handle_login,
            style="Accent.TButton"
        ).pack(pady=10, ipady=5, fill="x")
        
        ttk.Button(
            frame,
            text="Forgot Password?",
            command=self.handle_password_recovery
        ).pack(pady=5, ipady=3, fill="x")

    def show_vault_ui(self):
        """Main password vault UI"""
        self.clear_ui()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Add Password Tab
        add_frame = ttk.Frame(self.notebook)
        self.setup_add_password_ui(add_frame)
        self.notebook.add(add_frame, text="Add Password")
        
        # Manage Passwords Tab
        view_frame = ttk.Frame(self.notebook)
        self.setup_view_passwords_ui(view_frame)
        self.notebook.add(view_frame, text="Manage Passwords")

    def setup_add_password_ui(self, frame):
        """Password entry form"""
        form_frame = ttk.Frame(frame, padding=15)
        form_frame.pack(expand=True, fill="both")
        
        ttk.Label(form_frame, text="Website:").grid(row=0, column=0, sticky="w", pady=5)
        self.website_entry = ttk.Entry(form_frame)
        self.website_entry.grid(row=0, column=1, pady=5, sticky="ew")
        
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = ttk.Entry(form_frame)
        self.username_entry.grid(row=1, column=1, pady=5, sticky="ew")
        
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=2, column=1, sticky="ew")
        
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side="left", expand=True, fill="x")
        
        ttk.Button(
            password_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(self.password_entry.get()),
            width=3
        ).pack(side="left", padx=5)
        
        ttk.Button(
            form_frame,
            text="💾 Save Password",
            command=self.save_password,
            style="Accent.TButton"
        ).grid(row=3, columnspan=2, pady=15, sticky="ew")
        
        form_frame.columnconfigure(1, weight=1)

    def setup_view_passwords_ui(self, frame):
        """Password management table"""
        main_frame = ttk.Frame(frame)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.passwords_tree = ttk.Treeview(
            main_frame,
            columns=("Website", "Username", "Password"),
            show="headings",
            selectmode="browse"
        )
        
        self.passwords_tree.heading("Website", text="🌐 Website")
        self.passwords_tree.heading("Username", text="👤 Username")
        self.passwords_tree.heading("Password", text="🔑 Password")
        
        for col in ("Website", "Username", "Password"):
            self.passwords_tree.column(col, width=150, anchor="w")
        
        self.passwords_tree.pack(expand=True, fill="both", pady=(0, 10))
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x")
        
        ttk.Button(
            btn_frame,
            text="📋 Copy",
            command=self.copy_selected_password
        ).pack(side="left", expand=True, padx=5)
        
        ttk.Button(
            btn_frame,
            text="✏️ Edit",
            command=self.edit_selected_password
        ).pack(side="left", expand=True, padx=5)
        
        ttk.Button(
            btn_frame,
            text="🗑️ Delete",
            command=self.delete_selected_password,
            style="Danger.TButton"
        ).pack(side="left", expand=True, padx=5)
        
        self.refresh_passwords_list()

    # ================= PASSWORD MANAGEMENT =================
    def refresh_passwords_list(self):
        """Reload passwords into the Treeview"""
        self.passwords_tree.delete(*self.passwords_tree.get_children())
        conn = self.get_db_connection()
        try:
            for website, username, encrypted_pwd in conn.execute("SELECT website, username, password FROM passwords"):
                decrypted_pwd = decrypt_data(encrypted_pwd, self.encryption_key)
                self.passwords_tree.insert("", "end", values=(website, username, "•" * len(decrypted_pwd)))
        finally:
            conn.close()

    def save_password(self):
        """Save new password to database"""
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not all([website, username, password]):
            messagebox.showerror("Error", "All fields are required!")
            return
        
        try:
            encrypted_pwd = encrypt_data(password, self.encryption_key)
            conn = self.get_db_connection()
            conn.execute("""
                INSERT OR REPLACE INTO passwords (website, username, password)
                VALUES (?, ?, ?)
            """, (website, username, encrypted_pwd))
            conn.commit()
            messagebox.showinfo("Success", "Password saved securely!")
            self.clear_entry_fields()
            self.refresh_passwords_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")
        finally:
            conn.close()

    def copy_selected_password(self):
        """Copy selected password to clipboard"""
        selected = self.passwords_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No password selected!")
            return
        
        website = self.passwords_tree.item(selected, "values")[0]
        conn = self.get_db_connection()
        try:
            encrypted_pwd = conn.execute(
                "SELECT password FROM passwords WHERE website = ?", 
                (website,)
            ).fetchone()[0]
            decrypted_pwd = decrypt_data(encrypted_pwd, self.encryption_key)
            pyperclip.copy(decrypted_pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")
        finally:
            conn.close()

    def edit_selected_password(self):
        """Edit existing password entry"""
        selected = self.passwords_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No password selected!")
            return
        
        website, username, _ = self.passwords_tree.item(selected, "values")
        conn = self.get_db_connection()
        try:
            encrypted_pwd = conn.execute(
                "SELECT password FROM passwords WHERE website = ?", 
                (website,)
            ).fetchone()[0]
            current_password = decrypt_data(encrypted_pwd, self.encryption_key)
            
            # Create edit dialog
            edit_window = tk.Toplevel(self.root)
            edit_window.title("Edit Password")
            edit_window.geometry("400x250")
            edit_window.configure(bg="#2d2d2d")
            
            ttk.Label(edit_window, text="Edit Password", font=("Segoe UI", 12, "bold")).pack(pady=10)
            
            form_frame = ttk.Frame(edit_window, padding=15)
            form_frame.pack(expand=True)
            
            ttk.Label(form_frame, text="Website:").grid(row=0, column=0, sticky="w", pady=5)
            website_entry = ttk.Entry(form_frame)
            website_entry.grid(row=0, column=1, pady=5, sticky="ew")
            website_entry.insert(0, website)
            
            ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
            username_entry = ttk.Entry(form_frame)
            username_entry.grid(row=1, column=1, pady=5, sticky="ew")
            username_entry.insert(0, username)
            
            ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
            password_entry = ttk.Entry(form_frame, show="*")
            password_entry.grid(row=2, column=1, pady=5, sticky="ew")
            password_entry.insert(0, current_password)
            
            btn_frame = ttk.Frame(form_frame)
            btn_frame.grid(row=3, columnspan=2, pady=15, sticky="e")
            
            ttk.Button(
                btn_frame,
                text="Cancel",
                command=edit_window.destroy
            ).pack(side="right", padx=5)
            
            ttk.Button(
                btn_frame,
                text="Save",
                command=lambda: self.save_edit(
                    edit_window, website, 
                    website_entry.get(),
                    username_entry.get(),
                    password_entry.get()
                ),
                style="Accent.TButton"
            ).pack(side="right")
            
            form_frame.columnconfigure(1, weight=1)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit: {str(e)}")
        finally:
            conn.close()

    def save_edit(self, window, old_website, new_website, username, password):
        """Save edited password"""
        if not all([new_website, username, password]):
            messagebox.showerror("Error", "All fields are required!")
            return
        
        try:
            encrypted_pwd = encrypt_data(password, self.encryption_key)
            conn = self.get_db_connection()
            
            if new_website != old_website:
                conn.execute("DELETE FROM passwords WHERE website = ?", (old_website,))
            
            conn.execute("""
                INSERT OR REPLACE INTO passwords (website, username, password)
                VALUES (?, ?, ?)
            """, (new_website, username, encrypted_pwd))
            conn.commit()
            window.destroy()
            self.refresh_passwords_list()
            messagebox.showinfo("Success", "Changes saved!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")
        finally:
            conn.close()

    def delete_selected_password(self):
        """Delete selected password entry"""
        selected = self.passwords_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No password selected!")
            return
        
        website = self.passwords_tree.item(selected, "values")[0]
        if messagebox.askyesno("Confirm Delete", f"Delete password for {website}?", icon="warning"):
            conn = self.get_db_connection()
            try:
                conn.execute("DELETE FROM passwords WHERE website = ?", (website,))
                conn.commit()
                self.refresh_passwords_list()
                messagebox.showinfo("Deleted", "Password entry removed")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete: {str(e)}")
            finally:
                conn.close()

    # ================= UTILITY METHODS =================
    def handle_first_time_setup(self):
        """Handle master password setup"""
        password = self.pwd_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return
        
        self.master_password_hash = hash_password(password)
        self.save_master_password(password)
        messagebox.showinfo("Success", "Master password set!")
        self.show_vault_ui()

    def handle_login(self):
        """Handle regular login"""
        password = self.pwd_entry.get()
        if verify_password(self.master_password_hash, password):
            self.show_vault_ui()
        else:
            messagebox.showerror("Error", "Wrong password!")

    def handle_password_recovery(self):
        """Reset all data"""
        if messagebox.askyesno("Warning", "This will DELETE ALL PASSWORDS!\nAre you sure?", icon="warning"):
            try:
                os.remove("vault.db")
                os.remove("secret.key")
                self.master_password_hash = None
                self.show_setup_ui()
                messagebox.showinfo("Reset Complete", "All data erased. Please set a new master password.")
            except Exception as e:
                messagebox.showerror("Error", f"Reset failed: {str(e)}")

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("Copied", "Text copied to clipboard!")

    def clear_entry_fields(self):
        """Clear all input fields"""
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def clear_ui(self):
        """Destroy all widgets"""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()