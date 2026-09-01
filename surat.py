import sqlite3
from flask import Flask, request

app = Flask(__name__)

# ❌ ZAAFİYET 1: Hardcoded API Secret Key
SURAT_KARGO_API_KEY = "SURAT_SEC_KEY_2026_PROD_998877665544332211"

@app.route("/api/kargo-sorgu")
def kargo_sorgu():
    # Kullanıcıdan gelen parametre (Source)
    takip_no = request.args.get("takipNo")

    conn = sqlite3.connect("surat_kargo.db")
    cursor = conn.cursor()
    
    # ❌ ZAAFİYET 2: SQL Injection (Sink)
    query = "SELECT * FROM kargo_gonderileri WHERE takip_no = '" + str(takip_no) + "'"
    cursor.execute(query) # CodeQL bu noktayı doğrudan Yakalar...!
    
    result = cursor.fetchall()
    return {"status": "ok", "data": result}
