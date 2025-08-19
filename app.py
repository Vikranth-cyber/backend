from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import datetime
import csv
import qrcode
import io
from io import BytesIO
from zipfile import ZipFile
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import barcode
from barcode.writer import ImageWriter
from barcode import Code128, Code39
import json

app = Flask(__name__)

# Configure DB
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'database.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app,
     origins=[
         "http://localhost:5173", 
         "https://frontend-six-peach-11.vercel.app"
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    is_manufacturer = db.Column(db.Boolean, default=False)
    manufacturer_name = db.Column(db.String(100))
    preferences = db.Column(db.String(500), default=json.dumps({
        'theme': 'light',
        'notifications': True,
        'language': 'en'
    }))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), unique=True, nullable=False)
    manufacturer = db.Column(db.String(100), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    expiry_date = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='products')

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

# Helpers
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
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def home():
    return jsonify({"message": "API running"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ['username', 'password', 'manufacturer_name']):
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = User(
        username=data['username'],
        password=hashed,
        email=data.get('email'),
        phone=data.get('phone'),
        is_manufacturer=True,  # All registered users are manufacturers
        manufacturer_name=data['manufacturer_name'],
        preferences=json.dumps({
            'theme': 'light',
            'notifications': True,
            'language': 'en'
        })
    )
    db.session.add(user)
    db.session.commit()

    # Automatically log in after registration
    token = jwt.encode({
        'username': user.username,
        'is_manufacturer': user.is_manufacturer,
        'manufacturer_name': user.manufacturer_name,
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'token': token,
        'is_manufacturer': user.is_manufacturer,
        'manufacturer_name': user.manufacturer_name
    }), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'username': user.username,
        'is_manufacturer': user.is_manufacturer,
        'manufacturer_name': user.manufacturer_name,
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'token': token,
        'is_manufacturer': user.is_manufacturer,
        'manufacturer_name': user.manufacturer_name
    })

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'phone': current_user.phone,
        'is_manufacturer': current_user.is_manufacturer,
        'manufacturer_name': current_user.manufacturer_name,
        'preferences': json.loads(current_user.preferences)
    })

@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    # Validate username if changed
    if 'username' in data and data['username'] != current_user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already exists'}), 400
        current_user.username = data['username']
    
    if 'email' in data:
        current_user.email = data['email']
    if 'phone' in data:
        current_user.phone = data['phone']
    if 'manufacturer_name' in data and current_user.is_manufacturer:
        current_user.manufacturer_name = data['manufacturer_name']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': {
            'username': current_user.username,
            'email': current_user.email,
            'phone': current_user.phone,
            'is_manufacturer': current_user.is_manufacturer,
            'manufacturer_name': current_user.manufacturer_name,
            'preferences': json.loads(current_user.preferences)
        }
    })

@app.route('/change_password', methods=['POST'])
@token_required
def change_password(current_user):
    data = request.get_json()
    if not data or not all(k in data for k in ['current_password', 'new_password']):
        return jsonify({'message': 'Current and new password required'}), 400
    
    if not check_password_hash(current_user.password, data['current_password']):
        return jsonify({'message': 'Current password is incorrect'}), 400
    
    if len(data['new_password']) < 8:
        return jsonify({'message': 'New password must be at least 8 characters'}), 400
    
    current_user.password = generate_password_hash(data['new_password'], method='pbkdf2:sha256')
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'})

@app.route('/update_preferences', methods=['POST'])
@token_required
def update_preferences(current_user):
    data = request.get_json()
    if not data or 'preferences' not in data:
        return jsonify({'message': 'Preferences data required'}), 400
    
    try:
        # Validate preferences structure
        preferences = data['preferences']
        if not isinstance(preferences, dict):
            raise ValueError("Preferences must be an object")
        
        # Update only valid preference fields
        current_prefs = json.loads(current_user.preferences)
        
        if 'theme' in preferences and preferences['theme'] in ['light', 'dark']:
            current_prefs['theme'] = preferences['theme']
        
        if 'notifications' in preferences and isinstance(preferences['notifications'], bool):
            current_prefs['notifications'] = preferences['notifications']
        
        if 'language' in preferences and preferences['language'] in ['en', 'es', 'fr', 'de']:
            current_prefs['language'] = preferences['language']
        
        current_user.preferences = json.dumps(current_prefs)
        db.session.commit()
        
        return jsonify({
            'message': 'Preferences updated successfully',
            'preferences': current_prefs
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 400

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

    product = Product(
        product_id=data['product_id'],
        manufacturer=data['manufacturer'],
        product_name=data.get('product_name', ''),
        expiry_date=data.get('expiry_date', ''),
        user_id=current_user.id
    )
    db.session.add(product)
    db.session.commit()

    return jsonify({'message': 'Product added'}), 201

@app.route('/upload_csv', methods=['POST'])
@token_required
def upload_csv(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can upload products'}), 403

    file = request.files.get('file')
    code_type = request.form.get('code_type', 'qr').lower()
    barcode_type = request.form.get('barcode_type', 'code128').lower()
    
    if not file or not file.filename.endswith('.csv'):
        return jsonify({'message': 'CSV file required'}), 400

    try:
        csv_data = file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(csv_data)
        
        required_fields = ['unique_id', 'manufacturer', 'product_name', 'expiry_date']
        missing_in_rows = []
        
        missing_in_header = [field for field in required_fields if field not in reader.fieldnames]
        if missing_in_header:
            return jsonify({
                'message': f'Missing required columns in CSV header: {", ".join(missing_in_header)}',
                'missing_fields': missing_in_header
            }), 400
        
        for i, row in enumerate(reader, start=2):
            missing_fields = [field for field in required_fields if not row.get(field, '').strip()]
            if missing_fields:
                missing_in_rows.append({
                    'row': i,
                    'missing_fields': missing_fields
                })
        
        if missing_in_rows:
            return jsonify({
                'message': 'Missing required values in some rows',
                'missing_data': missing_in_rows,
                'total_errors': len(missing_in_rows)
            }), 400
        
        file.seek(0)
        csv_data = file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(csv_data)
        processed = []

        zip_buffer = BytesIO()
        with ZipFile(zip_buffer, 'w') as zip_file:
            for row in reader:
                product_id = row.get('unique_id', '').strip()
                manufacturer = row.get('manufacturer', '').strip()
                product_name = row.get('product_name', '').strip()
                expiry_date = row.get('expiry_date', '').strip()

                if not Product.query.filter_by(product_id=product_id).first():
                    db.session.add(Product(
                        product_id=product_id,
                        manufacturer=manufacturer,
                        product_name=product_name,
                        expiry_date=expiry_date,
                        user_id=current_user.id
                    ))
                    processed.append(product_id)

                # Generate the requested code type
                if code_type == 'qr':
                    img = qrcode.make(product_id)
                    img_io = BytesIO()
                    img.save(img_io, 'PNG')
                    img_io.seek(0)
                    zip_file.writestr(f"{product_id}.png", img_io.read())
                elif code_type == 'barcode':
                    try:
                        if barcode_type == 'code128':
                            code = Code128(product_id, writer=ImageWriter())
                        elif barcode_type == 'code39':
                            code = Code39(product_id, writer=ImageWriter())
                        else:
                            code = Code128(product_id, writer=ImageWriter())

                        img_io = BytesIO()
                        code.write(img_io, options={'write_text': False})
                        img_io.seek(0)
                        zip_file.writestr(f"{product_id}.png", img_io.read())
                    except Exception as e:
                        print(f"Error generating barcode for {product_id}: {str(e)}")
                        continue

        db.session.commit()
        zip_buffer.seek(0)
        filename = f'{code_type}_codes.zip' if code_type == 'qr' else f'{barcode_type}_codes.zip'
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/sample_csv', methods=['GET'])
@token_required
def download_sample_csv(current_user):
    if not current_user.is_manufacturer:
        return jsonify({'message': 'Only manufacturers can download samples'}), 403
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['unique_id', 'manufacturer', 'product_name', 'expiry_date'])
    writer.writerow(['PROD001', current_user.manufacturer_name or 'Your Company', 'Sample Product', '2024-12-31'])
    csv_data = output.getvalue()
    output.close()
    
    csv_bytes = io.BytesIO()
    csv_bytes.write(csv_data.encode('utf-8'))
    csv_bytes.seek(0)
    
    response = send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name='sample_products.csv'
    )
    response.call_on_close(lambda: csv_bytes.close())
    return response

@app.route('/scan', methods=['POST'])
def scan_product():
    data = request.get_json()
    raw = data['product_id']
    product_id = raw.split(' ')[1] if raw.startswith("ID:") else raw.strip()
    name, phone, pincode = data['name'], data['phone'], data['pincode']

    product = Product.query.filter_by(product_id=product_id).first()
    if not product:
        return jsonify({
            'status': 'invalid',
            'message': 'Product not found',
            'scanned_code': raw
        }), 200

    previous_scans = ScanLog.query.filter_by(product_id=product_id).order_by(ScanLog.timestamp.asc()).all()

    new_scan = ScanLog(product_id=product_id, name=name, phone_number=phone, pincode=pincode, product=product)
    db.session.add(new_scan)
    db.session.commit()

    if previous_scans:  # duplicate scan
        create_notification(new_scan.id, f"⚠️ Duplicate scan for {product_id} by {name}")
        return jsonify({
            "status": "duplicate",
            "message": "This product has already been scanned before",
            "product": {"product_id": product.product_id, "manufacturer": product.manufacturer},
            "first_scan": {
                "name": previous_scans[0].name,
                "phone": previous_scans[0].phone_number,
                "pincode": previous_scans[0].pincode,
                "timestamp": previous_scans[0].timestamp.isoformat()
            }
        })

    # no notification for first scan
    return jsonify({
        "status": "genuine",
        "message": "First valid scan - Product is genuine",
        "product": {"product_id": product.product_id, "manufacturer": product.manufacturer}
    })


@app.route('/scans', methods=['GET'])
@token_required
def get_scans(current_user):
    try:
        if current_user.is_manufacturer:
            scans = (ScanLog.query
                    .join(Product)
                    .filter(Product.user_id == current_user.id)
                    .order_by(ScanLog.timestamp.desc())
                    .all())
        else:
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
        
    notifications = (Notification.query
                    .join(ScanLog)
                    .join(Product)
                    .filter(Product.user_id == current_user.id)
                    .order_by(Notification.timestamp.desc())
                    .all())
                    
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
        
    products = Product.query.filter_by(user_id=current_user.id).all()
    result = []
    for product in products:
        scan_count = ScanLog.query.filter_by(product_id=product.product_id).count()
        result.append({
            "product_id": product.product_id,
            "manufacturer": product.manufacturer,
            "product_name": product.product_name,
            "expiry_date": product.expiry_date,
            "status": "Not scanned" if scan_count == 0 else "Scanned",
            "scan_count": scan_count
        })
    return jsonify({"products": result})

def init_db():
    with app.app_context():
        db.create_all()
        # only add admin/sample if tables are empty
        if User.query.count() == 0:
            admin = User(
                username="admin",
                password=generate_password_hash("admin123", method='pbkdf2:sha256'),
                email="admin@example.com",
                phone="1234567890",
                is_manufacturer=True,
                manufacturer_name="Admin Manufacturer"
            )
            db.session.add(admin)
            db.session.commit()

            sample = Product(
                product_id="TEST123",
                manufacturer="Sample Manufacturer",
                product_name="Sample Product",
                expiry_date="2024-12-31",
                user_id=admin.id
            )
            db.session.add(sample)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)