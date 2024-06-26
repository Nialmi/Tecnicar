from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from .models import User, Customer, Vehicle

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Correo', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember = BooleanField('Recordarme')
    submit = SubmitField('Iniciar Sesión')


class CustomerRegistrationForm(FlaskForm):
    customer_document = IntegerField('Documento del Cliente', validators=[DataRequired(), NumberRange(min=0)])
    customer_name = StringField('Nombre del Cliente', validators=[DataRequired()])
    customer_last_name = StringField('Apellido del Cliente', validators=[DataRequired()])
    customer_phone = IntegerField('Telefono del Cliente', validators=[DataRequired(), NumberRange(min=0)])
    vehicle_license_plate = StringField('Matricula del vehiculo', validators=[DataRequired()])
    vehicle_model = StringField('Modelo', validators=[DataRequired()])
    vehicle_color = StringField('Color', validators=[DataRequired()])
    vehicle_type = SelectField('Tipo de Vehículo', choices=[
        ('Seleccione', 'Seleccione'),
        ('Sedan', 'Sedan'),
        ('Compacto', 'Compacto'),
        ('Camioneta', 'Camioneta'),
        ('SUV', 'SUV'),
        ('Minivan', 'Minivan'),
        ('Furgoneta', 'Furgoneta') ])
    aseguradora = SelectField('Aseguradora', choices=[
        ('Seleccione', 'Seleccione'),
        ('Angloamericana', 'Angloamericana'),
        ('General de Seguros', 'General de Seguros'),
        ('CONFEDOM', 'CONFEDOM'),
        ('One Alliance', 'One Alliance') ])
    workshop= SelectField('Seleccione Taller', choices=[
        ('Seleccione', 'Seleccione'),
        ('Beisbolistas', 'Beisbolistas'),
        ('Los prados', 'Los prados')])
    submit = SubmitField('Registrar')

    def validate_vehicle_license_plate(self, vehicle_license_plate):
        vehicle = Vehicle.query.filter_by(license_plate=vehicle_license_plate.data).first()
        if vehicle:
            raise ValidationError('This license plate is already registered. Please choose a different one.')

class UserRegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirme Contraseña', validators=[DataRequired(), EqualTo('password')])
    role= SelectField('Seleccione El Rol', choices=[
        ('admin', 'admin'),
        ('operator', 'operator')])
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')
        
class VehicleStatusForm(FlaskForm):
    status = SelectField('Estado del Vehículo', choices=[
        ('Seleccione', 'Seleccione'),
        ('Vehiculo en liquidación', 'Vehiculo en liquidación'),
        ('Orden Aprobada', 'Orden Aprobada'),
        ('Recepción de Repuestos', 'Recepción de Repuestos'),
        ('Desarme', 'Desarme'),
        ('Desabolladura', 'Desabolladura'),
        ('Preparación', 'Preparación'),
        ('Pintura','Pintura'),
        ('Ensamble', 'Ensamble'),
        ('Brillado', 'Brillado'),
        ('Lavado', 'Lavado'),
        ('Terminación', 'Terminación'),
        ('Entrega', 'Entrega')])
    comentario = TextAreaField('Comentarios')
    submit = SubmitField('Actualizar Estado')
