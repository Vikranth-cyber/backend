from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), unique=True, nullable=False)
    manufacturer = db.Column(db.String(100), nullable=False)

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), db.ForeignKey('product.product_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    product = db.relationship('Product', backref='scans')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
def init_db():
    db.create_all()
