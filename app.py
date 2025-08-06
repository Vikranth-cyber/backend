# app.py (updated)
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import datetime
import csv
import qrcode
from io import BytesIO
from zipfile import ZipFile
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)

# Configure DB
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'database.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'

CORS(app, resources={r"/*": {"origins": [
    "https://frontend-cpekzuer2-vikranths-projects-c28738f4.vercel.app"
]}}, supports_credentials=True)

db = SQLAlchemy(app)

# Models (same as before)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_manufacturer = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), unique=True, nullable=False)
    manufacturer = db.Column(db.String(100), nullable=False)

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), db.ForeignKey('product.product_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    pincode = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    product = db.relationship('Product', backref='scans')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_log.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    scan = db.relationship('ScanLog', backref='notifications')

# Helpers (same as before)
def create_notification(scan_id, message):
    notification = Notification(scan_id=scan_id, message=message)
    db.session.add(notification)
    db.session.commit()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes (same as before)
@app.route('/')
def home():
    return jsonify({"message": "API running"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ['username', 'password', 'is_manufacturer']):
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = User(username=data['username'], password=hashed, is_manufacturer=data['is_manufacturer'])
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'username': user.username,
        'is_manufacturer': user.is_manufacturer,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])

    return jsonify({'token': token, 'is_manufacturer': user.is_manufacturer})

@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can add products'}), 403
    data = request.get_json()
    if not all(k in data for k in ['product_id', 'manufacturer']):
        return jsonify({'message': 'All fields required'}), 400
    if Product.query.filter_by(product_id=data['product_id']).first():
        return jsonify({'message': 'Product ID exists'}), 400

    product = Product(product_id=data['product_id'], manufacturer=data['manufacturer'])
    db.session.add(product)
    db.session.commit()

    return jsonify({'message': 'Product added'}), 201

@app.route('/upload_csv', methods=['POST'])
@token_required
def upload_csv(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can upload products'}), 403

    file = request.files.get('file')
    if not file or not file.filename.endswith('.csv'):
        return jsonify({'message': 'CSV file required'}), 400

    reader = csv.DictReader(file.read().decode('utf-8').splitlines())
    processed = []

    # Create QR codes in memory
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, 'w') as zip_file:
        for row in reader:
            product_id = row.get('unique_id', '').strip()
            manufacturer = row.get('manufacturer', '').strip()
            if not product_id or not manufacturer:
                continue

            # Save to DB
            if not Product.query.filter_by(product_id=product_id).first():
                db.session.add(Product(product_id=product_id, manufacturer=manufacturer))
                processed.append(product_id)

            # Generate QR
            img = qrcode.make(product_id)
            img_io = BytesIO()
            img.save(img_io)
            img_io.seek(0)
            zip_file.writestr(f"{product_id}.png", img_io.read())

    db.session.commit()

    zip_buffer.seek(0)
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='qrcodes.zip')

@app.route('/scan', methods=['POST'])
def scan_product():
    data = request.get_json()
    raw = data['product_id']
    
    # Extract just the ID part (VCT123) from "ID: VCT123 Name: ..."
    product_id = raw.split(' ')[1] if raw.startswith("ID:") else raw.strip()
    
    name = data['name']
    phone = data['phone']
    pincode = data['pincode']

    product = Product.query.filter_by(product_id=product_id).first()
    if not product:
        return jsonify({
            'status': 'invalid',
            'message': 'Product not found',
            'scanned_code': raw
        }), 200

    existing_scan = ScanLog.query.filter_by(product_id=product_id, phone_number=phone).first()
    if existing_scan:
        create_notification(existing_scan.id, f"Duplicate scan by {name} for {product_id}")
        return jsonify({
            "status": "already_scanned",
            "message": "This product was already scanned with this phone number",
            "product": {"product_id": product.product_id, "manufacturer": product.manufacturer},
            "first_scan": {
                "name": existing_scan.name,
                "phone": existing_scan.phone_number,
                "pincode": existing_scan.pincode,
                "timestamp": existing_scan.timestamp.isoformat()
            }
        })

    previous_scans = ScanLog.query.filter_by(product_id=product_id).order_by(ScanLog.timestamp.asc()).all()
    new_scan = ScanLog(product_id=product_id, name=name, phone_number=phone, pincode=pincode, product=product)
    db.session.add(new_scan)
    db.session.commit()

    if previous_scans:
        create_notification(new_scan.id, f"Multiple scans for {product_id} by {name}")
        return jsonify({
            "status": "genuine",
            "message": "Product is genuine but scanned before",
            "product": {"product_id": product.product_id, "manufacturer": product.manufacturer},
            "first_scan": {
                "name": previous_scans[0].name,
                "phone": previous_scans[0].phone_number,
                "pincode": previous_scans[0].pincode,
                "timestamp": previous_scans[0].timestamp.isoformat()
            }
        })

    return jsonify({
        "status": "genuine",
        "message": "First valid scan - Product is genuine",
        "product": {"product_id": product.product_id, "manufacturer": product.manufacturer}
    })

@app.route('/scans', methods=['GET'])
@token_required
def get_scans(current_user):
    try:
        scans = ScanLog.query.join(Product).order_by(ScanLog.timestamp.desc()).all()
        result = []
        for scan in scans:
            result.append({
                "id": scan.id,
                "product_id": scan.product_id,
                "manufacturer": scan.product.manufacturer,
                "name": scan.name,
                "phone": scan.phone_number,
                "pincode": scan.pincode,
                "timestamp": scan.timestamp.isoformat(),
                "status": "First scan" if ScanLog.query.filter_by(product_id=scan.product_id).count() == 1 else "Duplicate scan"
            })
        return jsonify({"scans": result})
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can view notifications'}), 403
        
    notifications = Notification.query.join(ScanLog).order_by(Notification.timestamp.desc()).all()
    result = []
    for notification in notifications:
        result.append({
            "id": notification.id,
            "message": notification.message,
            "timestamp": notification.timestamp.isoformat(),
            "product_id": notification.scan.product_id,
            "scanned_by": notification.scan.name,
            "phone": notification.scan.phone_number,
            "pincode": notification.scan.pincode
        })
    return jsonify({"notifications": result})

@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can view products'}), 403
        
    products = Product.query.all()
    result = []
    for product in products:
        scan_count = ScanLog.query.filter_by(product_id=product.product_id).count()
        result.append({
            "product_id": product.product_id,
            "manufacturer": product.manufacturer,
            "status": "Not scanned" if scan_count == 0 else "Scanned",
            "scan_count": scan_count
        })
    return jsonify({"products": result})

# Init DB
def init_db():
    with app.app_context():
        db.create_all()
        if Product.query.count() == 0:
            sample = Product(product_id="TEST123", manufacturer="Sample Manufacturer")
            db.session.add(sample)
        if User.query.count() == 0:
            admin = User(username="admin", password=generate_password_hash("admin123", method='pbkdf2:sha256'), is_manufacturer=True)
            db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)