import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import os

# Funções principais
def execute_action(action, entries):
    try:
        if action == "generate":
            subprocess.run(["python3", "main.py"], input=b"1\n0\n", check=True)
            messagebox.showinfo("Sucesso", "Chaves RSA geradas com sucesso!")
            show_main_page()
            return
        
        if action in ["encrypt", "decrypt", "sign", "verify"]:
            # Tentar carregar chaves se não existirem
            if not os.path.exists('public_key.txt') or not os.path.exists('private_key.txt'):
                messagebox.showwarning("Aviso", "Gere as chaves RSA primeiro (opção Gerar Chaves)")
                return

        if action in ["encrypt", "decrypt", "sign"]:
            filename = entries[0].get().strip()
            if not filename:
                messagebox.showwarning("Aviso", "Digite o nome do arquivo.")
                return
            subprocess.run(["python3", "main.py"], input=f"{actions_codes[action]}\n{filename}\n0\n".encode(), check=True)
            messagebox.showinfo("Sucesso", f"Ação '{action}' executada com sucesso!")
            show_main_page()
            return

        if action == "verify":
            file_original = entries[0].get().strip()
            file_sig = entries[1].get().strip()
            if not file_original or not file_sig:
                messagebox.showwarning("Aviso", "Preencha ambos os arquivos.")
                return
            input_data = f"5\n{file_original}\n{file_sig}\n0\n".encode()
            subprocess.run(["python3", "main.py"], input=input_data, check=True)
            messagebox.showinfo("Verificação", "Verificação de assinatura concluída.")
            show_main_page()
            return

        if action == "edit":
            filename = entries[0].get().strip()
            if not filename:
                messagebox.showwarning("Aviso", "Digite o nome do arquivo.")
                return
            edit_file(filename)
            show_main_page()
            return

    except subprocess.CalledProcessError:
        messagebox.showerror("Erro", "Ocorreu um problema ao executar a ação.")


# Função de edição de arquivo
def edit_file(filename):
    if not os.path.exists(filename):
        messagebox.showerror("Erro", f"O arquivo '{filename}' não foi encontrado.")
        return

    editor = tk.Toplevel(root)
    editor.title(f"Editando: {filename}")
    editor.geometry("700x500")
    editor.configure(bg="#FFF8DC")

    text_area = scrolledtext.ScrolledText(editor, wrap=tk.WORD, font=("Consolas", 11))
    text_area.pack(expand=True, fill='both', padx=10, pady=10)

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        text_area.insert(tk.END, f.read())

    def save_changes():
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(text_area.get("1.0", tk.END))
        messagebox.showinfo("Salvo", f"Alterações salvas em '{filename}'.")
        editor.destroy()

    def cancel_edit():
        if messagebox.askyesno("Cancelar", "Descartar alterações?"):
            editor.destroy()

    frame_btns = tk.Frame(editor, bg="#FFF8DC")
    frame_btns.pack(pady=10)
    tk.Button(frame_btns, text="Salvar", bg="#28a745", fg="white", width=12, relief="ridge",
              bd=2, font=("Helvetica", 11, "bold"), command=save_changes).pack(side=tk.LEFT, padx=10)
    tk.Button(frame_btns, text="Cancelar", bg="#dc3545", fg="white", width=12, relief="ridge",
              bd=2, font=("Helvetica", 11, "bold"), command=cancel_edit).pack(side=tk.LEFT, padx=10)


# --- Interface principal ---
root = tk.Tk()
root.title("Gerador/Verificador de Assinaturas RSA")
root.geometry("650x500")
root.configure(bg="#FFF8DC")  # Fundo ocre claro
root.resizable(False, False)

actions_codes = {
    "generate": 1,
    "encrypt": 2,
    "decrypt": 3,
    "sign": 4,
    "verify": 5,
}

# ---------------- PÁGINAS ---------------- #

def clear_window():
    for widget in root.winfo_children():
        widget.destroy()

def styled_button(master, text, color, command):
    """Botão retangular com leve curvatura e sombra simulada."""
    btn = tk.Button(master, text=text, font=("Helvetica", 12, "bold"), fg="white",
                    bg=color, activebackground=color, activeforeground="white",
                    relief="flat", width=24, height=1, bd=0,
                    highlightthickness=0, padx=6, pady=6,
                    command=command)
    # Curvatura leve via corner radius simulado (flat + padding)
    btn.configure(borderwidth=2, relief="ridge")
    return btn

# Página principal
def show_main_page():
    clear_window()

    tk.Label(root, text="Gerador e Verificador de Assinaturas RSA", bg="#FFF8DC",
             font=("Helvetica", 17, "bold")).pack(pady=25)

    buttons = tk.Frame(root, bg="#FFF8DC")
    buttons.pack()

    styled_button(buttons, "Gerar Chaves", "#007bff", lambda: show_action_page("generate")).pack(pady=8)
    styled_button(buttons, "Criptografar Arquivo", "#007bff", lambda: show_action_page("encrypt")).pack(pady=8)
    styled_button(buttons, "Descriptografar Arquivo", "#007bff", lambda: show_action_page("decrypt")).pack(pady=8)
    styled_button(buttons, "Assinar Arquivo", "#007bff", lambda: show_action_page("sign")).pack(pady=8)
    styled_button(buttons, "Verificar Assinatura", "#007bff", lambda: show_action_page("verify")).pack(pady=8)
    styled_button(buttons, "Editar Arquivo", "#f0ad4e", lambda: show_action_page("edit")).pack(pady=8)


# Página de ação
def show_action_page(action):
    clear_window()
    tk.Label(root, text=f"Ação: {action.capitalize()}", bg="#FFF8DC", font=("Helvetica", 15, "bold")).pack(pady=20)

    input_frame = tk.Frame(root, bg="#FFF8DC")
    input_frame.pack(pady=30)

    entries = []

    if action in ["encrypt", "decrypt", "sign", "edit"]:
        tk.Label(input_frame, text="Digite o nome do arquivo:", bg="#FFF8DC", font=("Helvetica", 12)).pack(pady=5)
        entry = tk.Entry(input_frame, width=45, font=("Helvetica", 12))
        entry.pack(pady=10, ipady=6)
        entries.append(entry)

    elif action == "verify":
        tk.Label(input_frame, text="Arquivo original:", bg="#FFF8DC", font=("Helvetica", 12)).pack(pady=5)
        entry1 = tk.Entry(input_frame, width=45, font=("Helvetica", 12))
        entry1.pack(pady=10, ipady=6)
        tk.Label(input_frame, text="Arquivo de assinatura (.sig):", bg="#FFF8DC", font=("Helvetica", 12)).pack(pady=5)
        entry2 = tk.Entry(input_frame, width=45, font=("Helvetica", 12))
        entry2.pack(pady=10, ipady=6)
        entries.extend([entry1, entry2])

    if action == "generate":
        execute_action(action, [])
        return

    # Botões de envio e retorno
    buttons_frame = tk.Frame(root, bg="#FFF8DC")
    buttons_frame.pack(pady=30)

    styled_button(buttons_frame, "Enviar", "#007bff", lambda: execute_action(action, entries)).pack(pady=6)
    styled_button(buttons_frame, "Voltar", "#6c757d", show_main_page).pack(pady=6)


# Inicia na página principal
show_main_page()
root.mainloop()
