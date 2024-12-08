import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import threading
import time

# Список заблокированных IP-адресов
blocked_ips = set()

# Словарь для отслеживания подозрительных IP-адресов и правил
suspicious_ips = {}

# Правила обнаружения подозрительного трафика
suspicious_rules = {
    "large_packet": lambda pkt: len(pkt) > 1000,  # Аномально большой пакет
    "repeated_requests": lambda pkt: pkt.haslayer(IP) and recent_requests.get(pkt[IP].src, 0) > 10,  # Повторяющиеся запросы
}

# Словарь для отслеживания повторяющихся запросов
recent_requests = {}

# Словарь для отслеживания уже обработанных пакетов
processed_packets = {}

# Флаг для остановки сниффинга
stop_sniffing = False

# Флаг для отслеживания состояния сниффинга
is_sniffing = False

# Функция для анализа трафика
def analyze_traffic(pkt):
    global stop_sniffing
    if stop_sniffing:
        return

    if pkt.haslayer(IP):
        ip = pkt[IP].src
        port = pkt[IP].sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else "N/A"
        size = len(pkt)

        # Проверяем, был ли пакет уже обработан
        packet_key = (ip, port, size)
        if packet_key in processed_packets:
            return

        # Отмечаем пакет как обработанный
        processed_packets[packet_key] = True

        recent_requests[ip] = recent_requests.get(ip, 0) + 1

    for rule_name, rule_func in suspicious_rules.items():
        if rule_func(pkt):
            if pkt.haslayer(IP):
                ip = pkt[IP].src
                if ip not in suspicious_ips:
                    suspicious_ips[ip] = rule_name
                    print(f"Подозрительный трафик обнаружен: {rule_name} (IP: {ip})")
                    root.after(0, update_suspicious_list)  # Обновляем интерфейс в главном потоке
            break

    # Отображение всех IP-адресов
    if pkt.haslayer(IP):
        ip = pkt[IP].src
        port = pkt[IP].sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else "N/A"
        size = len(pkt)
        root.after(0, lambda: update_all_ips_list(ip, port, size))

# Функция для блокировки IP-адреса
def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            messagebox.showinfo("Блокировка", f"IP-адрес {ip} заблокирован.")
            root.after(0, update_blocked_list)  # Обновляем интерфейс в главном потоке
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Ошибка", f"Не удалось заблокировать IP-адрес {ip}: {e}")

# Функция для разблокировки IP-адреса
def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            messagebox.showinfo("Разблокировка", f"IP-адрес {ip} разблокирован.")
            root.after(0, update_blocked_list)  # Обновляем интерфейс в главном потоке
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Ошибка", f"Не удалось разблокировать IP-адрес {ip}: {e}")

# Функция для запуска анализа трафика
def start_sniffing():
    global stop_sniffing, is_sniffing
    if is_sniffing:
        return
    stop_sniffing = False
    is_sniffing = True
    try:
        scapy.sniff(prn=analyze_traffic, store=False, stop_filter=lambda x: stop_sniffing)
    except scapy.error.Scapy_Exception:
        messagebox.showerror("Ошибка", "Интерфейс был выключен. Программа остановлена.")
        root.quit()
    finally:
        is_sniffing = False

# Функция для остановки анализа трафика
def stop_sniffing_func():
    global stop_sniffing
    stop_sniffing = True

# Создание графического интерфейса
root = tk.Tk()
root.title("Блокировка подозрительного трафика")
root.geometry("800x600")  # Увеличиваем размер окна

# Центрирование окна
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry('{}x{}+{}+{}'.format(width, height, x, y))

# Главный фрейм для центрирования
main_frame = tk.Frame(root)
main_frame.place(relx=0.5, rely=0.5, anchor="center")

# Список подозрительных IP-адресов
suspicious_frame = tk.Frame(main_frame)
suspicious_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

suspicious_listbox = tk.Listbox(suspicious_frame, width=30, height=10)
suspicious_listbox.pack(fill="both", expand=True)

# Список заблокированных IP-адресов
blocked_frame = tk.Frame(main_frame)
blocked_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

blocked_listbox = tk.Listbox(blocked_frame, width=30, height=10)
blocked_listbox.pack(fill="both", expand=True)

# Список всех IP-адресов
all_ips_frame = tk.Frame(main_frame)
all_ips_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

all_ips_table = ttk.Treeview(all_ips_frame, columns=("IP", "Port", "Size"), show="headings", height=15)
all_ips_table.heading("IP", text="IP Address")
all_ips_table.heading("Port", text="Port")
all_ips_table.heading("Size", text="Size")
all_ips_table.pack(fill="both", expand=True)

# Кнопка для блокировки выбранного IP-адреса
def block_selected_ip():
    try:
        selected_ip = suspicious_listbox.get(suspicious_listbox.curselection()).split()[0]  # Извлекаем только IP-адрес
        block_ip(selected_ip)
    except tk.TclError:
        messagebox.showerror("Ошибка", "Выберите IP-адрес для блокировки.")

block_button = tk.Button(main_frame, text="Заблокировать", command=block_selected_ip, width=15)
block_button.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

# Кнопка для разблокировки выбранного IP-адреса
def unblock_selected_ip():
    try:
        selected_ip = blocked_listbox.get(blocked_listbox.curselection())
        unblock_ip(selected_ip)
    except tk.TclError:
        messagebox.showerror("Ошибка", "Выберите IP-адрес для разблокировки.")

unblock_button = tk.Button(main_frame, text="Разблокировать", command=unblock_selected_ip, width=15)
unblock_button.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")

# Кнопка для запуска сниффинга
start_button = tk.Button(main_frame, text="Старт", command=lambda: threading.Thread(target=start_sniffing).start(), width=15)
start_button.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

# Кнопка для остановки сниффинга
stop_button = tk.Button(main_frame, text="Стоп", command=stop_sniffing_func, width=15)
stop_button.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")

# Функция для обновления списка подозрительных IP-адресов
def update_suspicious_list():
    suspicious_listbox.delete(0, tk.END)
    for ip, rule in suspicious_ips.items():
        suspicious_listbox.insert(tk.END, f"{ip} (Правило: {rule})")

# Функция для обновления списка заблокированных IP-адресов
def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    for ip in blocked_ips:
        blocked_listbox.insert(tk.END, ip)

# Функция для обновления списка всех IP-адресов
def update_all_ips_list(ip, port, size):
    all_ips_table.insert("", "end", values=(ip, port, size))

# Остановка программы при закрытии окна
def on_closing():
    global stop_sniffing
    stop_sniffing = True
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
