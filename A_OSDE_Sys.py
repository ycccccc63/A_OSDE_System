import hashlib
import random
import tkinter as tk
from tkinter import messagebox, ttk


class A_OSDE_Core:
    """非對稱單邊差值擴張法 (A-OSDE) 核心演算法[cite: 1]"""

    @staticmethod
    def get_hash_binary_bits(val: int, num_bits: int = 4) -> tuple[str, int]:
        """計算 SHA256 雜湊值，並取得最後 num_bits 的「二進位字串」與「整數值」[cite: 1]

        返回: (二進位字串, 整數值) 例如: ("0101", 5)
        """
        val_bytes = str(val).encode("utf-8")
        hash_hex = hashlib.sha256(val_bytes).hexdigest()
        # 取最後一個 hex 字符轉整數，再轉為 4 位元的二進位字串 (補零至 4 位)
        int_val = int(hash_hex[-1], 16) & ((1 << num_bits) - 1)
        bin_str = format(int_val, f"0{num_bits}b")
        return bin_str, int_val

    @staticmethod
    def generate_anchors(key: int, length: int) -> list:
        """依據 Key 產生偽隨機錨點 (Anchor) 序列[cite: 1]"""
        rng = random.Random(key)
        return [rng.randint(10, 100) for _ in range(length)]

    @staticmethod
    def embed_secret(x: int, a: int, secret_bits_int: int, n_bits: int = 4) -> int:
        """差值擴張嵌入 4 個位元（整數型態）[cite: 1]"""
        d = x - a
        d_prime = (d << n_bits) + secret_bits_int
        return a + d_prime

    @staticmethod
    def extract_secret(
        x_prime: int, a: int, n_bits: int = 4
    ) -> tuple[str, int, int]:
        """提取驗證碼 (返回二進位字串、整數驗證碼、還原原始數值)[cite: 1]"""
        d_prime = x_prime - a
        mask = (1 << n_bits) - 1
        secret_int = d_prime & mask
        bin_str = format(secret_int, f"0{n_bits}b")
        d = d_prime >> n_bits
        x_orig = a + d
        return bin_str, secret_int, x_orig


class A_OSDE_App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("非對稱單邊差值擴張法 - 數字資料安全保障系統 (二進位驗證碼)")
        self.geometry("880x650")
        self.configure(bg="#f5f5f5")

        self.core = A_OSDE_Core()
        self.raw_data = []

        self._create_widgets()

    def _create_widgets(self):
        # 標題
        title_label = tk.Label(
            self,
            text="非對稱單邊差值擴張法 (A-OSDE) 資料防竄改系統",
            font=("Arial", 16, "bold"),
            bg="#f5f5f5",
            fg="#333333",
        )
        title_label.pack(pady=10)

        # 控制區塊
        control_frame = tk.LabelFrame(
            self, text=" 系統輸入與設定 ", font=("Arial", 11, "bold"), bg="#f5f5f5"
        )
        control_frame.pack(fill="x", padx=15, pady=5)

        # Key 輸入
        tk.Label(
            control_frame, text="PRNG 金鑰 (Key):", font=("Arial", 10), bg="#f5f5f5"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = tk.Entry(control_frame, width=15, font=("Arial", 10))
        self.key_entry.insert(0, "2026")
        self.key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 數字資料輸入
        tk.Label(
            control_frame,
            text="原始數字 (用逗號隔開):",
            font=("Arial", 10),
            bg="#f5f5f5",
        ).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.data_entry = tk.Entry(control_frame, width=45, font=("Arial", 10))
        self.data_entry.insert(0, "500, 1024, 750, 320, 999")
        self.data_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # 按鈕區
        btn_frame = tk.Frame(control_frame, bg="#f5f5f5")
        btn_frame.grid(row=2, column=0, columnspan=3, pady=10)

        rand_btn = tk.Button(
            btn_frame,
            text="🎲 產生隨機資料",
            command=self._generate_random_data,
            bg="#e0e0e0",
        )
        rand_btn.pack(side="left", padx=5)

        encode_btn = tk.Button(
            btn_frame,
            text="🔒 執行編碼保護",
            command=self._run_encoding,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
        )
        encode_btn.pack(side="left", padx=5)

        decode_btn = tk.Button(
            btn_frame,
            text="🔓 執行解碼與驗證",
            command=self._run_decoding,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold"),
        )
        decode_btn.pack(side="left", padx=5)

        # 提示標籤
        hint_label = tk.Label(
            self,
            text="💡 提示：編碼後可「雙擊表格中的保護資料欄位」修改數字，測試自動竄改偵測機制。",
            font=("Arial", 9, "italic"),
            fg="#666666",
            bg="#f5f5f5",
        )
        hint_label.pack(anchor="w", padx=15, pady=2)

        # 表格區塊
        table_frame = tk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        columns = ("idx", "raw", "anchor", "hash_bin", "protected", "recovered", "status")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=12
        )

        headers = {
            "idx": ("索引", 50),
            "raw": ("原始數值", 80),
            "anchor": ("錨點 (Anchor)", 90),
            "hash_bin": ("SHA256末4位(二進位)", 140),
            "protected": ("保護後數值 (可雙擊修改)", 160),
            "recovered": ("還原數值", 80),
            "status": ("自動驗證狀態", 120),
        }

        for col, (text, width) in headers.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="center")

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self._on_double_click)

    def _get_key(self):
        try:
            return int(self.key_entry.get().strip())
        except ValueError:
            messagebox.showerror("錯誤", "Key 必須為整數！")
            return None

    def _generate_random_data(self):
        random_nums = [random.randint(100, 2000) for _ in range(5)]
        self.data_entry.delete(0, tk.END)
        self.data_entry.insert(0, ", ".join(map(str, random_nums)))

    def _run_encoding(self):
        """編碼端流程[cite: 1]"""
        key = self._get_key()
        if key is None:
            return

        raw_str = self.data_entry.get().strip()
        try:
            self.raw_data = [int(x.strip()) for x in raw_str.split(",") if x.strip()]
        except ValueError:
            messagebox.showerror("錯誤", "原始資料請輸入以逗號分隔的整數！")
            return

        if not self.raw_data:
            messagebox.showwarning("警告", "請輸入至少一個數字！")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        anchors = self.core.generate_anchors(key, len(self.raw_data))

        for i, (x, a) in enumerate(zip(self.raw_data, anchors)):
            # 取得 SHA256 末 4 位的二進位字串與整數值[cite: 1]
            bin_str, h_bits_int = self.core.get_hash_binary_bits(x)
            
            # 差值擴張嵌入[cite: 1]
            x_prime = self.core.embed_secret(x, a, h_bits_int)

            # 顯示格式為 二進位 (例如: 0101)
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(i, x, a, bin_str, x_prime, "-", "已保護"),
            )

        messagebox.showinfo("成功", "編碼完成！已將 SHA256 末4位(二進位) 藏入資料中。")[cite: 1]

    def _run_decoding(self):
        """解碼端與自動竄改偵測流程[cite: 1]"""
        if not self.tree.get_children():
            messagebox.showwarning("警告", "請先進行編碼！")
            return

        key = self._get_key()
        if key is None:
            return

        items = self.tree.get_children()
        length = len(items)
        anchors = self.core.generate_anchors(key, length)

        for i, item in enumerate(items):
            current_values = list(self.tree.item(item, "values"))
            x_prime = int(current_values[4])
            a = anchors[i]

            # 1. 提取二進位驗證碼與還原數值[cite: 1]
            extracted_bin, extracted_int, restored_x = self.core.extract_secret(x_prime, a)

            # 2. 計算現況數值的 SHA256 二進位末4位[cite: 1]
            current_bin, current_int = self.core.get_hash_binary_bits(restored_x)

            # 3. 比對二進位驗證碼[cite: 1]
            if extracted_bin == current_bin:
                status_str = "✅ 正確原數值"
            else:
                status_str = "❌ 遭竄改"

            current_values[5] = restored_x
            current_values[6] = status_str
            self.tree.item(item, values=current_values)

        messagebox.showinfo("解碼完成", "自動竄改偵測與驗證流程已執行完畢！")[cite: 1]

    def _on_double_click(self, event):
        """雙擊修改『保護後數值』以模擬竄改數據[cite: 1]"""
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return

        column = self.tree.identify_column(event.x)
        if column != "#5":
            return

        item = self.tree.focus()
        if not item:
            return

        x, y, w, h = self.tree.bbox(item, column)
        value = self.tree.item(item, "values")[4]

        entry = tk.Entry(self.tree)
        entry.place(x=x, y=y, width=w, height=h)
        entry.insert(0, value)
        entry.focus()

        def save_edit(e=None):
            new_val = entry.get().strip()
            try:
                new_int = int(new_val)
                vals = list(self.tree.item(item, "values"))
                vals[4] = new_int
                vals[6] = "⚠️ 已修改(待驗證)"
                self.tree.item(item, values=vals)
            except ValueError:
                messagebox.showerror("錯誤", "修改值必須為整數！")
            finally:
                entry.destroy()

        entry.bind("<Return>", save_edit)
        entry.bind("<FocusOut>", lambda e: entry.destroy())


if __name__ == "__main__":
    app = A_OSDE_App()
    app.mainloop()A_OSDE_System.pyA_OSDE_System.py