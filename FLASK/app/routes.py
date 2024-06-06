from flask import render_template, url_for, flash, redirect, request, current_app as app
from flask_login import login_user, current_user, logout_user, login_required
from .forms import RegistrationForm, LoginForm, CustomerRegistrationForm, UserRegistrationForm
from .models import User, Customer, Vehicle
from . import db, bcrypt

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            if user.role == 'operator':
                return redirect(url_for('register_customer'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/register_customer', methods=['GET', 'POST'])
@login_required
def register_customer():
    if current_user.role != 'operator':
        return redirect(url_for('home'))
    form = CustomerRegistrationForm()
    if form.validate_on_submit():
        customer = Customer(name=form.customer_name.data)
        db.session.add(customer)
        db.session.commit()
        vehicle = Vehicle(model=form.vehicle_model.data, license_plate=form.vehicle_license_plate.data, owner=customer)
        db.session.add(vehicle)
        db.session.commit()
        flash('Customer and vehicle registered successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('register_customer.html', title='Register Customer', form=form)

# Administración
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html', title='Admin Dashboard')

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    vehicles = Vehicle.query.all()
    return render_template('admin_reports.html', title='Vehicle Reports', vehicles=vehicles)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    form = UserRegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_create_user.html', title='Create User', form=form)

@app.route('/admin/view_records')
@login_required
def admin_view_records():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    customers = Customer.query.all()
    return render_template('admin_view_records.html', title='View Records', customers=customers)