import pandas as pd
import qrcode
import os

def generate_qr_code(data):
    img = qrcode.make(data)
    return img

def process_csv_and_generate_qrs(file_path):
    df = pd.read_csv(file_path)

    if 'unique_id' not in df.columns:
        raise ValueError("CSV must contain a 'unique_id' column.")

    os.makedirs("static/qrcodes", exist_ok=True)
    qrs = []

    for index, row in df.iterrows():
        qr_data = row['unique_id']
        qr_image = generate_qr_code(qr_data)
        qr_path = os.path.join("static/qrcodes", f"{qr_data}.png")
        qr_image.save(qr_path)
        qrs.append({"id": qr_data, "path": qr_path})

    return qrs

def save_csv_with_qr(csv_path, output_path, qrs):
    df = pd.read_csv(csv_path)

    if 'unique_id' not in df.columns:
        raise ValueError("CSV must contain a 'unique_id' column.")

    for qr in qrs:
        df.loc[df['unique_id'] == qr["id"], "qr_path"] = qr["path"]

    df.to_csv(output_path, index=False)
