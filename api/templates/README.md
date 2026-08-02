# Server-side profiling templates

一般使用者不需要上傳 profiling traces、profiling plaintexts 或 profiling keys。
管理者必須先使用與目標相同的晶片、韌體、時脈、探棒、取樣率、trigger 與 trace 長度收集 profiling 資料。

AES-128：

    python build_template.py --aes 128 --traces PROFILE_TRACES.npy --plaintexts PROFILE_TEXTIN.npy --keys PROFILE_KEYS.npy

AES-256：

    python build_template.py --aes 256 --traces PROFILE_TRACES.npy --plaintexts PROFILE_TEXTIN.npy --keys PROFILE_KEYS.npy

預設輸出：
- aes128_default.npz
- aes256_default.npz

keys 必須每條 profiling trace 對應一把已知 key；AES-128 shape 為 (N,16)，AES-256 為 (N,32)。
建模器會拒絕樣本不足的 HW 群，避免產生不可靠 covariance。
NPZ 只保存統計模板，不保存原始 traces。