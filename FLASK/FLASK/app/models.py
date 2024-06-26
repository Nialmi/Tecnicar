from datetime import datetime
from flask_login import UserMixin
from . import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='operator')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone= db.Column(db.Integer, nullable= False)
    vehicles = db.relationship('Vehicle', backref='owner', lazy=True)

    def __repr__(self):
        return f"Customer('{self.name}')"

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_plate = db.Column(db.String(100), unique=True, nullable=False)
    model = db.Column(db.String(100), nullable=False)
    vehicle_color = db.Column(db.String(50), nullable=False)
    vehicle_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(60), default='Levantamiento')
    username = db.Column(db.String(120), nullable=True)
    workshop = db.Column(db.String(120), nullable=False)
    comentario = db.Column(db.String(500))
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)

    def __repr__(self):
        return f"Vehicle('{self.model}', '{self.license_plate}', '{self.vehicle_color}', '{self.vehicle_type}')"
