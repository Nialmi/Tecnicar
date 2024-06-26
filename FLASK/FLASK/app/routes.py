from flask import render_template, url_for, flash, redirect, request, current_app as app, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from .forms import RegistrationForm, LoginForm, CustomerRegistrationForm, UserRegistrationForm, VehicleStatusForm
from .models import User, Customer, Vehicle
from . import db, bcrypt
import qrcode
import qrcode.image.svg
from io import BytesIO
from flask import send_file
import base64
from sqlalchemy.exc import IntegrityError
from rpa import send_whatsapp_message  # Importar la función del archivo rpa.py


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
        flash('Su Cuenta fue Creada con Exito!, Puede Iniciar Sesion', 'success')
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
            flash('Inicio de sesión sin éxito. Por favor revisa el correo electrónico y la contraseña', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Has Cerrado Sesión Correctamente.', 'info')
    return redirect(url_for('home'))

@app.route('/register_customer', methods=['GET', 'POST'])
@login_required
def register_customer():
    if current_user.role != 'operator':
        return redirect(url_for('home'))
    form = CustomerRegistrationForm()
    qr_img = None
    if form.validate_on_submit():
        try:
            customer = Customer(document=form.customer_document.data, name=form.customer_name.data, last_name=form.customer_last_name.data, phone=form.customer_phone.data )
            db.session.add(customer)
            db.session.commit()
            vehicle = Vehicle(model=form.vehicle_model.data, license_plate=form.vehicle_license_plate.data,vehicle_color=form.vehicle_color.data, vehicle_type=form.vehicle_type.data, owner=customer, workshop=form.workshop.data)
            db.session.add(vehicle)
            db.session.commit()

            # Generar el código QR
            qr_data = url_for('vehicle_info', vehicle_id=vehicle.id, _external=True)
            img = qrcode.make(qr_data)
            buf = BytesIO()
            img.save(buf)
            buf.seek(0)
            qr_img = base64.b64encode(buf.getvalue()).decode('utf-8')  # Convertir a Base64

            flash('¡Cliente y vehículo registrados exitosamente!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Esta matrícula ya está registrada. Por favor verifique los datos.', 'danger')
    return render_template('register_customer.html', title='Register Customer', form=form, qr_img=qr_img)


# Administración
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html', title='Admin Dashboard')

@app.route('/admin/reports', methods=['GET', 'POST'])
@login_required
def admin_reports():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    # Obtener los estados distintos de la base de datos
    status = Vehicle.query.with_entities(Vehicle.status).distinct().all()
    
    # Verifica si el campo workshop existe en la base de datos
    workshops = []
    if hasattr(Vehicle, 'workshop'):
        workshops = Vehicle.query.with_entities(Vehicle.workshop).distinct().all()

    return render_template('admin_reports.html', title='Vehicle Reports', status=status, workshops=workshops)

@app.route('/get_report_data', methods=['POST'])
@login_required
def get_report_data():
    state_filter = request.form.get('state_filter', '')
    workshop_filter = request.form.get('workshop_filter', '')

    query = Vehicle.query
    if state_filter:
        query = query.filter_by(status=state_filter)
    if workshop_filter:
        query = query.filter_by(workshop=workshop_filter)
    
    vehicles = query.all()

    # Procesar los datos para el gráfico agrupado por taller y estado
    data = {}
    for vehicle in vehicles:
        workshop = vehicle.workshop
        status = vehicle.status
        if workshop not in data:
            data[workshop] = {}
        if status in data[workshop]:
            data[workshop][status] += 1
        else:
            data[workshop][status] = 1

    return jsonify(data)

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
        flash('¡Usuario creado exitosamente!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_create_user.html', title='Create User', form=form)

@app.route('/admin/view_records')
@login_required
def admin_view_records():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    customers = Customer.query.all()
    return render_template('admin_view_records.html', title='View Records', customers=customers)

@app.route('/vehicle/<int:vehicle_id>', methods=['GET', 'POST'])
@login_required
def vehicle_info(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    customer = Customer.query.get_or_404(vehicle.customer_id)
    form = VehicleStatusForm()

    if form.validate_on_submit():
        vehicle.status = form.status.data
        vehicle.username = current_user.username
        vehicle.comentario = form.comentario.data
        db.session.commit()
        flash('Estado del vehículo actualizado con éxito', 'success')

        # Enviar mensaje de WhatsApp
        message = f"Hola {customer.name}, el estado de su vehículo ha sido actualizado a: {vehicle.status}"
        send_whatsapp_message(customer.phone, message)

        return redirect(url_for('vehicle_info', vehicle_id=vehicle.id))

    form.status.data = vehicle.status  # Establece el valor por defecto como el estado actual
    return render_template('vehicle_info.html', vehicle=vehicle, customer=customer, form=form, hide_navbar=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)