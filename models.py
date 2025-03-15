from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()
DB_NAME = "healthData.db"
# Association tables for many-to-many relationships
patient_conditions = db.Table('patient_conditions',
                              db.Column('patient_id', db.Integer, db.ForeignKey('user_personal_data.patient_id'),
                                        primary_key=True),
                              db.Column('condition_id', db.Integer, db.ForeignKey('conditions.condition_id'),
                                        primary_key=True)
                              )

patient_medications = db.Table('patient_medications',
                               db.Column('patient_id', db.Integer, db.ForeignKey('user_personal_data.patient_id'),
                                         primary_key=True),
                               db.Column('medication_id', db.Integer, db.ForeignKey('medications.medication_id'),
                                         primary_key=True)
                               )


class Account(db.Model, UserMixin):
    """
    UserMixin simplifies integration with flask-login by providing:
    is_authenticated, is_active, is_anonymous, and get_id
    """
    __tablename__ = 'account'

    account_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Patient")

    # Relationships
    personal_data = db.relationship('UserPersonalData', back_populates='account', lazy='dynamic',
                                    cascade="all, delete-orphan")

    def set_password(self, password):
        if len(password) < 8 or len(password) > 16:
            raise ValueError("Password must be between 8 and 16 characters")
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return str(self.account_id)

    def to_dict(self):
        return {
            'account_id': self.account_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'role': self.role
        }


class Conditions(db.Model):
    __tablename__ = 'conditions'

    condition_id = db.Column(db.Integer, primary_key=True)
    condition_name = db.Column(db.String(100), nullable=False, unique=True, index=True)

    def to_dict(self):
        return {
            'condition_id': self.condition_id,
            'condition_name': self.condition_name
        }


class Medications(db.Model):
    __tablename__ = 'medications'

    medication_id = db.Column(db.Integer, primary_key=True)
    medication_name = db.Column(db.String(100), nullable=False, unique=True, index=True)

    def to_dict(self):
        return {
            'medication_id': self.medication_id,
            'medication_name': self.medication_name
        }


class DietType(db.Model):
    __tablename__ = 'diet_type'

    diet_type_id = db.Column(db.Integer, primary_key=True)
    diet_type = db.Column(db.String(50), nullable=False, unique=True, index=True)

    # Relationships
    patients = db.relationship('UserPersonalData', back_populates='diet', lazy='dynamic')

    def to_dict(self):
        return {
            'diet_type_id': self.diet_type_id,
            'diet_type': self.diet_type
        }


class PhysicalActivityLevel(db.Model):
    __tablename__ = 'physical_activity_level'

    pal_id = db.Column(db.Integer, primary_key=True)
    activity_level = db.Column(db.String(50), nullable=False, unique=True, index=True)

    # Relationships
    patients = db.relationship('UserPersonalData', back_populates='activity', lazy='dynamic')

    def to_dict(self):
        return {
            'pal_id': self.pal_id,
            'activity_level': self.activity_level
        }


class AlcoholConsumption(db.Model):
    __tablename__ = 'alcohol_consumption'

    alcohol_consumption_id = db.Column(db.Integer, primary_key=True)
    consumption_level = db.Column(db.String(50), index=True)

    # Relationships
    patients = db.relationship('UserPersonalData', back_populates='alcohol', lazy='dynamic')

    def to_dict(self):
        return {
            'alcohol_consumption_id': self.alcohol_consumption_id,
            'consumption_level': self.consumption_level
        }


class UserPersonalData(db.Model):
    __tablename__ = 'user_personal_data'

    patient_id = db.Column(db.Integer, primary_key=True)
    user_account_id = db.Column(db.Integer, db.ForeignKey('account.account_id'), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(1), nullable=False)
    date_of_visit = db.Column(db.Date, default=None)
    previous_visits = db.Column(db.Integer, default=0)
    diet_type_id = db.Column(db.Integer, db.ForeignKey('diet_type.diet_type_id'))
    physical_activity_level_id = db.Column(db.Integer, db.ForeignKey('physical_activity_level.pal_id'))
    is_smoker = db.Column(db.Boolean, default=True)  # True for yes, False for no
    alcohol_consumption_id = db.Column(db.Integer, db.ForeignKey('alcohol_consumption.alcohol_consumption_id'))
    blood_pressure = db.Column(db.String(20))
    weight_kg = db.Column(db.Integer)
    height_cm = db.Column(db.Integer)
    bmi = db.Column(db.Numeric(5, 2))

    # Relationships - many-to-many
    conditions = db.relationship('Conditions', secondary=patient_conditions, lazy='dynamic',
                                 backref=db.backref('patients', lazy='dynamic'))
    medications = db.relationship('Medications', secondary=patient_medications, lazy='dynamic',
                                  backref=db.backref('patients', lazy='dynamic'))

    # Relationships - one-to-many
    device_data = db.relationship('DeviceDataQuery', back_populates='patient', lazy='dynamic',
                                  cascade="all, delete-orphan")

    # Relationships - many-to-one
    account = db.relationship('Account', back_populates='personal_data')
    diet = db.relationship('DietType', back_populates='patients')
    activity = db.relationship('PhysicalActivityLevel', back_populates='patients')
    alcohol = db.relationship('AlcoholConsumption', back_populates='patients')

    def calculate_bmi(self):
        if self.weight_kg and self.height_cm and self.height_cm > 0:
            height_m = self.height_cm / 100
            self.bmi = round(self.weight_kg / (height_m * height_m), 1)
        return self.bmi

    def to_dict(self):
        return {
            'patient_id': self.patient_id,
            'user_account_id': self.user_account_id,
            'age': self.age,
            'gender': self.gender,
            'date_of_visit': self.date_of_visit.strftime('%Y-%m-%d') if self.date_of_visit else None,
            'previous_visits': self.previous_visits,
            'diet_type_id': self.diet_type_id,
            'physical_activity_level_id': self.physical_activity_level_id,
            'is_smoker': self.is_smoker,
            'alcohol_consumption_id': self.alcohol_consumption_id,
            'blood_pressure': self.blood_pressure,
            'weight_kg': self.weight_kg,
            'height_cm': self.height_cm,
            'bmi': float(self.bmi) if self.bmi else None,
            'conditions': [c.to_dict() for c in self.conditions],
            'medications': [m.to_dict() for m in self.medications]
        }


class InterstitialFluidElement(db.Model):
    __tablename__ = 'interstitial_fluid_element'

    element_id = db.Column(db.Integer, primary_key=True)
    element_name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    upper_limit = db.Column(db.Numeric(5, 3))
    lower_limit = db.Column(db.Numeric(5, 3))
    upper_critical_limit = db.Column(db.Numeric(5, 3))
    lower_critical_limit = db.Column(db.Numeric(5, 3))

    # Relationships
    device_data = db.relationship('DeviceDataQuery', back_populates='element', lazy='dynamic',
                                  cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'element_id': self.element_id,
            'element_name': self.element_name,
            'upper_limit': float(self.upper_limit) if self.upper_limit else None,
            'lower_limit': float(self.lower_limit) if self.lower_limit else None,
            'upper_critical_limit': float(self.upper_critical_limit) if self.upper_critical_limit else None,
            'lower_critical_limit': float(self.lower_critical_limit) if self.lower_critical_limit else None
        }


class DeviceDataQuery(db.Model):
    __tablename__ = 'device_data_query'

    query_id = db.Column(db.Integer, primary_key=True)
    date_logged = db.Column(db.Date, default=datetime.utcnow)
    time_stamp = db.Column(db.Time, default=datetime.utcnow)
    recorded_value = db.Column(db.Integer)
    element_id = db.Column(db.Integer, db.ForeignKey('interstitial_fluid_element.element_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user_personal_data.patient_id'), nullable=False)

    # Relationships
    patient = db.relationship('UserPersonalData', back_populates='device_data')
    element = db.relationship('InterstitialFluidElement', back_populates='device_data')

    def to_dict(self):
        return {
            'query_id': self.query_id,
            'date_logged': self.date_logged.strftime('%Y-%m-%d') if self.date_logged else None,
            'time_stamp': self.time_stamp.strftime('%H:%M:%S') if self.time_stamp else None,
            'recorded_value': self.recorded_value,
            'element_id': self.element_id,
            'element_name': self.element.element_name if self.element else None,
            'user_id': self.user_id
        }