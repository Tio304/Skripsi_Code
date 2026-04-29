# Hybrid Network Intrusion Detection System (NIDS)

Sistem ini adalah Hybrid NIDS real-time yang menggabungkan:
- Signature-based detection (rule engine + threat intel)
- ML anomaly detection (XGBoost)
- Analyst feedback loop untuk retraining

Tujuan utama: mendeteksi ancaman yang sudah diketahui (signature) sekaligus tetap menangkap pola baru/unknown (ML).

## 1) Arsitektur Singkat

Alur utama:
1. Packet capture dari interface jaringan (Scapy)
2. Stage signature memeriksa rule bawaan + Snort/Suricata + IOC intel
3. Stage ML memberi skor anomali menggunakan model XGBoost
4. Policy engine menentukan aksi berdasarkan mode operasi
5. Alert disimpan ke JSONL dan ditampilkan di dashboard
6. Keputusan analyst (ignored/resolved) disimpan sebagai data feedback retraining

## 2) Fitur Utama

### A. Policy mode
- detect-only: hanya deteksi, tidak blokir
- block-signature: blokir IP ketika signature match
- soc-queue-ml: event ML tertentu masuk antrean SOC

### B. Enrichment signature dan intel
- Parser Snort rules
- Parser Suricata rules
- OTX IOC ingestion (API key atau file IOC lokal)
- Generator OTX-Suricata rules helper

### C. Dashboard analyst
- Daftar alert dan agregasi event
- Filter status pending/resolved/ignored
- Aksi Ignore/Resolve
- Blacklist panel (feed publik + local blocked/detected IP)

### D. Model lifecycle
- Retraining dari dataset NFv3
- Feedback analyst ikut dimasukkan ke training set
- Arsip model per run
- Registry run model
- Rollback ke model lama

## 3) Struktur File Penting

### Engine dan dashboard
- nids_engine.py: engine utama capture + detection + policy
- flask_app.py: dashboard Flask + REST API
- dashboard.py: dashboard Streamlit (opsional/legacy)
- start_all.ps1: launcher engine + dashboard

### Training dan evaluasi
- train_xgboost_model.py: training model + feedback ingestion + registry/history
- compare_training_metrics.py: ringkasan metrik antar run
- rollback_model.py: rollback model aktif

### Data dan artefak runtime
- alerts.json: alert JSONL hasil deteksi
- analyst_feedback.jsonl: keputusan analyst untuk retraining
- blocked_ips.jsonl: log IP yang diblokir signature mode
- model.json: model aktif
- model_meta.json: metadata model aktif (threshold rekomendasi)
- models/: arsip model dan metadata per run

### Dataset
- Dataset/NF-CICIDS2018-v3.csv
- Dataset/NF-UNSW-NB15-v3.csv
- Dataset/NetFlow_v3_Features.csv
- Dataset/MASTER_DATASET.csv

## 4) Prasyarat

- OS: Windows (script launcher PowerShell)
- Python virtual env pada folder .venv
- Jalankan terminal sebagai Administrator untuk live sniffing (disarankan)

Contoh aktivasi venv:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& ".\\.venv\\Scripts\\Activate.ps1"
```

Jika environment belum terpasang library, instal minimal:

```powershell
& ".\\.venv\\Scripts\\python.exe" -m pip install flask flask-cors scapy xgboost pandas numpy
```

## 5) Konfigurasi .env

Opsional namun direkomendasikan:

```env
NIDS_OTX_API_KEY=isi_api_key_otx_anda
OTX_API_KEY=alternatif_nama_key
NIDS_OINKCODE=opsional_oinkcode_snort
```

Catatan:
- start_all.ps1 mencoba membaca NIDS_OTX_API_KEY, lalu fallback ke OTX_API_KEY.
- Jika OTX tidak tersedia, engine tetap bisa jalan dengan rule lokal/bawaan.

## 6) Menjalankan Sistem

### A. Jalankan cepat (mode default)

```powershell
.\start_all.ps1 -InterfaceName "Wi-Fi" -ModelPath "model.json" -PolicyMode "detect-only"
```

### B. Jalankan dengan block-signature

```powershell
.\start_all.ps1 -InterfaceName "Wi-Fi" -ModelPath "model.json" -PolicyMode "block-signature"
```

### C. Argumen penting start_all.ps1

- -InterfaceName: nama interface jaringan
- -ModelPath: path model XGBoost
- -PolicyMode: detect-only | block-signature | soc-queue-ml
- -SnortRulesPath: path file/folder snort rules
- -SuricataRulesPath: path file/folder suricata rules
- -OtxApiKey: override API key OTX
- -OtxIocFile: IOC lokal (opsional)
- -OtxMaxIocs: batas IOC OTX yang diambil

Dashboard akan tersedia di:
- http://localhost:5000

## 7) OTX Suricata Helper

Generate rules OTX-Suricata ke cache lokal:

```powershell
.\update_otx_suricata.ps1
```

Atau dengan key eksplisit:

```powershell
.\update_otx_suricata.ps1 -OtxApiKey "YOUR_KEY"
```

Setelah file rules jadi, launcher otomatis mencoba memakai folder:
- .cache/otx-suricata

## 8) Retraining, Evaluasi, Rollback

### A. Retraining model

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\train_xgboost_model.py --promote-if-better
```

Output utama retraining:
- model aktif: model.json, model_meta.json
- arsip run: models/model_YYYYMMDD_HHMMSS.json
- history: training_history.json
- registry: model_registry.json

### B. Bandingkan metrik antar run

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\compare_training_metrics.py
```

### C. Lihat daftar run yang tersedia

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\rollback_model.py --list
```

### D. Rollback ke run tertentu

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\rollback_model.py --run-id 20260403_153000
```

## 9) Makna Status Analyst

- pending: alert belum diputuskan
- resolved: alert valid/ditangani (masuk label serangan pada feedback retraining)
- ignored: alert dianggap noise/false positive (masuk label benign pada feedback retraining)

Feedback disimpan ke analyst_feedback.jsonl dan digunakan saat retraining.

## 10) Troubleshooting Cepat

### A. Dashboard kosong atau tidak update
- Pastikan engine dan flask_app.py berjalan di terminal terpisah
- Cek file alerts.json bertambah

### B. OTX timeout
- Cek koneksi/proxy/firewall ke domain OTX
- Cek API key di .env
- Jika feed live timeout, sistem bisa tetap berjalan menggunakan data lokal/rules lain

### C. blocked_ips.jsonl tidak terisi
- Pastikan menjalankan policy mode block-signature
- Pastikan ada signature match pada traffic uji

### D. training_history.json atau model_registry.json belum ada
- File ini dibuat setelah retraining pertama

## 11) Checklist Cross-check Proposal

Gunakan mapping berikut saat review progres proposal:

1. Implementasi hybrid detection
- nids_engine.py

2. Dashboard monitoring dan workflow analyst
- flask_app.py
- alerts.json
- analyst_feedback.jsonl

3. Integrasi signature + threat intel
- nids_engine.py
- update_otx_suricata.ps1
- .cache/otx-suricata (jika sudah generate)

4. Kebijakan respons dan blocking
- nids_engine.py
- blocked_ips.jsonl

5. Retraining berbasis feedback
- train_xgboost_model.py
- analyst_feedback.jsonl

6. Evaluasi performa model
- compare_training_metrics.py
- training_history.json (setelah retraining)

7. Model versioning dan rollback
- train_xgboost_model.py
- rollback_model.py
- model_registry.json (setelah retraining)
- models/

## 12) Catatan Operasional

- Untuk uji akhir/sidang, siapkan bukti kombinasi:
	- source code
	- file output aktual (alerts, feedback, blocked, history)
	- screenshot dashboard
- Jalankan retraining minimal sekali agar artefak history/registry terbentuk.

