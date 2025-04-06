#!/usr/bin/env python3
"""
Database seed script for the health monitoring application.
Creates admin and patient users, reference data, and sample records.
Run this script to initialize the database with sample data.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create the application
from app import create_app

app = create_app()


def create_users():
    """
    Create admin user and sample patients with specified passwords.
    """
    from models import db, Account

    # Create admin user
    admin = Account(
        first_name="Admin",
        last_name="User",
        email="admin@example.com",
        role="Admin"
    )
    admin.set_password("Admin123!")
    db.session.add(admin)

    # Create 6 patient users
    patients = []

    # Group 1: Users with heart disease
    patient1 = Account(
        first_name="John",
        last_name="Doe",
        email="patient1@example.com",
        role="Patient"
    )
    patient1.set_password("Patient1!")
    db.session.add(patient1)
    patients.append(patient1)

    patient2 = Account(
        first_name="Mary",
        last_name="Johnson",
        email="patient2@example.com",
        role="Patient"
    )
    patient2.set_password("Patient2!")
    db.session.add(patient2)
    patients.append(patient2)

    # Group 2: Users with normal parameters
    patient3 = Account(
        first_name="Robert",
        last_name="Brown",
        email="patient3@example.com",
        role="Patient"
    )
    patient3.set_password("Patient3!")
    db.session.add(patient3)
    patients.append(patient3)

    patient4 = Account(
        first_name="Sarah",
        last_name="Williams",
        email="patient4@example.com",
        role="Patient"
    )
    patient4.set_password("Patient4!")
    db.session.add(patient4)
    patients.append(patient4)

    # Group 3: Users at risk of developing heart disease
    patient5 = Account(
        first_name="Michael",
        last_name="Smith",
        email="patient5@example.com",
        role="Patient"
    )
    patient5.set_password("Patient5!")
    db.session.add(patient5)
    patients.append(patient5)

    patient6 = Account(
        first_name="Jennifer",
        last_name="Davis",
        email="patient6@example.com",
        role="Patient"
    )
    patient6.set_password("Patient6!")
    db.session.add(patient6)
    patients.append(patient6)

    db.session.commit()
    print("Users created: admin and 6 patients with varying health profiles")

    return admin, patients


def create_reference_data():
    """
    Create all reference data: diet types, activity levels, conditions, etc.
    """
    from models import db, DietType, PhysicalActivityLevel, AlcoholConsumption, Conditions, InterstitialFluidElement, \
        Medications

    # Create diet types
    diet_types = [
        "Omnivore", "Vegetarian", "Vegan", "Pescatarian",
        "Paleo", "Keto", "Mediterranean", "Gluten-Free",
        "High Sodium", "Low Fiber", "High Cholesterol"
    ]
    for diet in diet_types:
        db.session.add(DietType(diet_type=diet))

    # Create physical activity levels
    activity_levels = [
        "Sedentary", "Lightly Active", "Moderately Active",
        "Very Active", "Extremely Active"
    ]
    for level in activity_levels:
        db.session.add(PhysicalActivityLevel(activity_level=level))

    # Create alcohol consumption levels
    consumption_levels = [
        "None", "Occasional", "Moderate", "Heavy"
    ]
    for level in consumption_levels:
        db.session.add(AlcoholConsumption(consumption_level=level))

    # Create health conditions
    conditions = [
        "Hypertension", "Diabetes Type 1", "Diabetes Type 2",
        "Asthma", "Arthritis", "Depression", "Anxiety",
        "Heart Disease", "Coronary Artery Disease", "Atrial Fibrillation",
        "Heart Failure", "Myocardial Infarction", "Obesity",
        "Hypothyroidism", "Hyperlipidemia", "Stroke",
        "Chronic Kidney Disease", "Sleep Apnea"
    ]
    for condition in conditions:
        db.session.add(Conditions(condition_name=condition))

    # Create medications
    medications = [
        "Lisinopril", "Metformin", "Insulin", "Albuterol",
        "Ibuprofen", "Aspirin", "Alprazolam", "Atorvastatin",
        "Levothyroxine", "Vitamin D", "Metoprolol", "Warfarin",
        "Clopidogrel", "Furosemide", "Losartan", "Amlodipine",
        "Carvedilol", "Rosuvastatin", "Ezetimibe"
    ]
    for medication in medications:
        db.session.add(Medications(medication_name=medication))

    # Create interstitial fluid elements (biomarkers)
    elements = [
        {
            "name": "Glucose",
            "lower_limit": 3.9,
            "upper_limit": 7.8,
            "lower_critical_limit": 3.0,
            "upper_critical_limit": 11.1
        },
        {
            "name": "Sodium",
            "lower_limit": 135.0,
            "upper_limit": 145.0,
            "lower_critical_limit": 120.0,
            "upper_critical_limit": 160.0
        },
        {
            "name": "Potassium",
            "lower_limit": 3.5,
            "upper_limit": 5.0,
            "lower_critical_limit": 2.5,
            "upper_critical_limit": 6.5
        },
        {
            "name": "Lactate",
            "lower_limit": 0.5,
            "upper_limit": 2.0,
            "lower_critical_limit": 0.2,
            "upper_critical_limit": 4.0
        },
        {
            "name": "Cortisol",
            "lower_limit": 5.0,
            "upper_limit": 25.0,
            "lower_critical_limit": 3.0,
            "upper_critical_limit": 40.0
        },
        {
            "name": "Apolipoprotein",
            "lower_limit": 1.0,
            "upper_limit": 2.0,
            "lower_critical_limit": 0.5,
            "upper_critical_limit": 2.5
        },
        {
            "name": "Troponin I",
            "lower_limit": 0.0,
            "upper_limit": 0.04,
            "lower_critical_limit": 0.0,
            "upper_critical_limit": 0.5
        },
        {
            "name": "BNP",
            "lower_limit": 0.0,
            "upper_limit": 100.0,
            "lower_critical_limit": 0.0,
            "upper_critical_limit": 500.0
        },
        {
            "name": "CRP",
            "lower_limit": 0.0,
            "upper_limit": 3.0,
            "lower_critical_limit": 0.0,
            "upper_critical_limit": 10.0
        },
        {
            "name": "Homocysteine",
            "lower_limit": 5.0,
            "upper_limit": 15.0,
            "lower_critical_limit": 3.0,
            "upper_critical_limit": 30.0
        },
        {
            "name": "HDL Cholesterol",
            "lower_limit": 1.0,
            "upper_limit": 2.0,
            "lower_critical_limit": 0.5,
            "upper_critical_limit": 3.0
        },
        {
            "name": "LDL Cholesterol",
            "lower_limit": 0.0,
            "upper_limit": 3.0,
            "lower_critical_limit": 0.0,
            "upper_critical_limit": 5.0
        }
    ]
    for element in elements:
        db.session.add(InterstitialFluidElement(
            element_name=element["name"],
            lower_limit=element["lower_limit"],
            upper_limit=element["upper_limit"],
            lower_critical_limit=element["lower_critical_limit"],
            upper_critical_limit=element["upper_critical_limit"]
        ))

    db.session.commit()
    print("Reference data created: diet types, activity levels, conditions, medications, fluid elements")


def create_patient_data(patients):
    """
    Create personal health data for patients.
    """
    from models import db, UserPersonalData, DietType, PhysicalActivityLevel, AlcoholConsumption, Conditions, \
        Medications

    # Get reference data IDs
    diet_types = {
        "Mediterranean": DietType.query.filter_by(diet_type="Mediterranean").first(),
        "High Sodium": DietType.query.filter_by(diet_type="High Sodium").first(),
        "High Cholesterol": DietType.query.filter_by(diet_type="High Cholesterol").first(),
        "Vegan": DietType.query.filter_by(diet_type="Vegan").first(),
        "Omnivore": DietType.query.filter_by(diet_type="Omnivore").first(),
        "Paleo": DietType.query.filter_by(diet_type="Paleo").first()
    }

    activity_levels = {
        "Sedentary": PhysicalActivityLevel.query.filter_by(activity_level="Sedentary").first(),
        "Lightly Active": PhysicalActivityLevel.query.filter_by(activity_level="Lightly Active").first(),
        "Moderately Active": PhysicalActivityLevel.query.filter_by(activity_level="Moderately Active").first(),
        "Very Active": PhysicalActivityLevel.query.filter_by(activity_level="Very Active").first()
    }

    alcohol_levels = {
        "None": AlcoholConsumption.query.filter_by(consumption_level="None").first(),
        "Occasional": AlcoholConsumption.query.filter_by(consumption_level="Occasional").first(),
        "Moderate": AlcoholConsumption.query.filter_by(consumption_level="Moderate").first(),
        "Heavy": AlcoholConsumption.query.filter_by(consumption_level="Heavy").first()
    }

    # Patient profiles
    patient_profiles = []

    # Group 1: Patients with heart disease (Users 0 and 1)
    patient_data1 = UserPersonalData(
        user_account_id=patients[0].account_id,
        age=65,
        gender="M",
        date_of_visit=datetime.now().date(),
        previous_visits=5,
        diet_type_id=diet_types["High Sodium"].diet_type_id,
        physical_activity_level_id=activity_levels["Sedentary"].pal_id,
        is_smoker=True,
        alcohol_consumption_id=alcohol_levels["Moderate"].alcohol_consumption_id,
        blood_pressure="165/95",
        weight_kg=98,
        height_cm=175
    )
    patient_data1.calculate_bmi()
    db.session.add(patient_data1)
    patient_profiles.append(patient_data1)

    patient_data2 = UserPersonalData(
        user_account_id=patients[1].account_id,
        age=72,
        gender="F",
        date_of_visit=datetime.now().date(),
        previous_visits=8,
        diet_type_id=diet_types["High Cholesterol"].diet_type_id,
        physical_activity_level_id=activity_levels["Lightly Active"].pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_levels["Occasional"].alcohol_consumption_id,
        blood_pressure="150/88",
        weight_kg=82,
        height_cm=162
    )
    patient_data2.calculate_bmi()
    db.session.add(patient_data2)
    patient_profiles.append(patient_data2)

    # Group 2: Patients with normal parameters (Users 2 and 3)
    patient_data3 = UserPersonalData(
        user_account_id=patients[2].account_id,
        age=35,
        gender="M",
        date_of_visit=datetime.now().date(),
        previous_visits=1,
        diet_type_id=diet_types["Mediterranean"].diet_type_id,
        physical_activity_level_id=activity_levels["Very Active"].pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_levels["Occasional"].alcohol_consumption_id,
        blood_pressure="118/78",
        weight_kg=78,
        height_cm=180
    )
    patient_data3.calculate_bmi()
    db.session.add(patient_data3)
    patient_profiles.append(patient_data3)

    patient_data4 = UserPersonalData(
        user_account_id=patients[3].account_id,
        age=29,
        gender="F",
        date_of_visit=datetime.now().date(),
        previous_visits=2,
        diet_type_id=diet_types["Vegan"].diet_type_id,
        physical_activity_level_id=activity_levels["Moderately Active"].pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_levels["None"].alcohol_consumption_id,
        blood_pressure="110/72",
        weight_kg=63,
        height_cm=167
    )
    patient_data4.calculate_bmi()
    db.session.add(patient_data4)
    patient_profiles.append(patient_data4)

    # Group 3: Patients at risk of developing heart disease (Users 4 and 5)
    patient_data5 = UserPersonalData(
        user_account_id=patients[4].account_id,
        age=48,
        gender="M",
        date_of_visit=datetime.now().date(),
        previous_visits=3,
        diet_type_id=diet_types["Omnivore"].diet_type_id,
        physical_activity_level_id=activity_levels["Lightly Active"].pal_id,
        is_smoker=True,
        alcohol_consumption_id=alcohol_levels["Moderate"].alcohol_consumption_id,
        blood_pressure="138/85",
        weight_kg=90,
        height_cm=178
    )
    patient_data5.calculate_bmi()
    db.session.add(patient_data5)
    patient_profiles.append(patient_data5)

    patient_data6 = UserPersonalData(
        user_account_id=patients[5].account_id,
        age=52,
        gender="F",
        date_of_visit=datetime.now().date(),
        previous_visits=2,
        diet_type_id=diet_types["Paleo"].diet_type_id,
        physical_activity_level_id=activity_levels["Lightly Active"].pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_levels["Moderate"].alcohol_consumption_id,
        blood_pressure="135/84",
        weight_kg=76,
        height_cm=165
    )
    patient_data6.calculate_bmi()
    db.session.add(patient_data6)
    patient_profiles.append(patient_data6)

    db.session.commit()

    # Add conditions and medications for each patient

    # Group 1: Heart disease patients
    patient1_conditions = ["Heart Disease", "Hypertension", "Coronary Artery Disease", "Hyperlipidemia"]
    for condition_name in patient1_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient_profiles[0].conditions.append(condition)

    patient1_medications = ["Lisinopril", "Metoprolol", "Aspirin", "Atorvastatin", "Clopidogrel"]
    for med_name in patient1_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient_profiles[0].medications.append(medication)

    patient2_conditions = ["Heart Disease", "Atrial Fibrillation", "Hypertension", "Diabetes Type 2"]
    for condition_name in patient2_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient_profiles[1].conditions.append(condition)

    patient2_medications = ["Warfarin", "Metformin", "Atorvastatin", "Furosemide"]
    for med_name in patient2_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient_profiles[1].medications.append(medication)

    # Group 2: Normal healthy patients
    patient3_conditions = ["Asthma"]  # Minor condition
    for condition_name in patient3_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient_profiles[2].conditions.append(condition)

    patient3_medications = ["Albuterol", "Vitamin D"]
    for med_name in patient3_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient_profiles[2].medications.append(medication)

    # Patient 4 has no conditions or medications

    # Group 3: At-risk patients
    patient5_conditions = ["Hypertension", "Obesity"]
    for condition_name in patient5_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient_profiles[4].conditions.append(condition)

    patient5_medications = ["Lisinopril", "Ibuprofen"]
    for med_name in patient5_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient_profiles[4].medications.append(medication)

    patient6_conditions = ["Hyperlipidemia", "Anxiety"]
    for condition_name in patient6_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient_profiles[5].conditions.append(condition)

    patient6_medications = ["Atorvastatin", "Alprazolam"]
    for med_name in patient6_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient_profiles[5].medications.append(medication)

    db.session.commit()
    print("Patient health data created with conditions and medications")

    return patient_profiles


def create_device_data(patient_profiles):
    """
    Create sample device measurement data for patients for different time periods:
    - Today
    - Past week
    - Past month
    - Past three months
    - Past six months
    - Past year
    """
    from models import db, InterstitialFluidElement, DeviceDataQuery

    # Get elements
    glucose = InterstitialFluidElement.query.filter_by(element_name="Glucose").first()
    sodium = InterstitialFluidElement.query.filter_by(element_name="Sodium").first()
    potassium = InterstitialFluidElement.query.filter_by(element_name="Potassium").first()
    lactate = InterstitialFluidElement.query.filter_by(element_name="Lactate").first()
    cortisol = InterstitialFluidElement.query.filter_by(element_name="Cortisol").first()
    apolipoprotein = InterstitialFluidElement.query.filter_by(element_name="Apolipoprotein").first()
    troponin = InterstitialFluidElement.query.filter_by(element_name="Troponin I").first()
    bnp = InterstitialFluidElement.query.filter_by(element_name="BNP").first()
    crp = InterstitialFluidElement.query.filter_by(element_name="CRP").first()
    homocysteine = InterstitialFluidElement.query.filter_by(element_name="Homocysteine").first()
    hdl = InterstitialFluidElement.query.filter_by(element_name="HDL Cholesterol").first()
    ldl = InterstitialFluidElement.query.filter_by(element_name="LDL Cholesterol").first()

    total_measurements = 0

    # Define time periods to generate data for
    today = datetime.now().date()
    time_periods = {
        "today": (today, today),
        "past_week": (today - timedelta(days=7), today),
        "past_month": (today - timedelta(days=30), today),
        "past_three_months": (today - timedelta(days=90), today),
        "past_six_months": (today - timedelta(days=180), today),
        "past_year": (today - timedelta(days=365), today)
    }

    # Function to generate a biomarker value based on patient group and progression over time
    def generate_biomarker_value(base_value, variation, patient_group, days_ago, trend_factor=0):
        """
        Generate a biomarker value with:
        - base_value: The typical value for this biomarker
        - variation: How much the value can vary randomly
        - patient_group: 0=heart disease, 1=normal, 2=at risk
        - days_ago: How many days ago this reading was taken
        - trend_factor: How much the value tends to change over time (can be positive or negative)
        """
        # Calculate time-based progression (more recent = worse for heart disease, better for healthy)
        time_progression = days_ago / 365.0  # Scale to 0-1 for a year

        if patient_group == 0:  # Heart disease - getting slightly worse over time
            progression_effect = -trend_factor * time_progression  # Negative means worse as time_progression decreases
        elif patient_group == 1:  # Normal - stable
            progression_effect = 0
        else:  # At risk - slowly getting worse
            progression_effect = -trend_factor * time_progression * 0.5  # Half the rate of decline

        adjusted_value = base_value + progression_effect
        return round(random.uniform(adjusted_value - variation, adjusted_value + variation))

    # Generate data for each patient and each time period
    for i, patient in enumerate(patient_profiles):
        # Determine which group the patient belongs to
        patient_group = i // 2  # 0 = heart disease, 1 = normal, 2 = at risk

        # Generate data for each time period
        for period_name, (start_date, end_date) in time_periods.items():
            # Calculate how many days to generate data for in this period
            days_in_period = (end_date - start_date).days + 1

            # Determine sampling frequency based on period length
            if period_name == "today":
                sampling_days = [0]  # Just today
            elif period_name == "past_week":
                sampling_days = range(days_in_period)  # Every day in the past week
            elif period_name == "past_month":
                sampling_days = range(0, days_in_period, 2)  # Every other day
            elif period_name == "past_three_months":
                sampling_days = range(0, days_in_period, 3)  # Every third day
            elif period_name == "past_six_months":
                sampling_days = range(0, days_in_period, 5)  # Every fifth day
            else:  # past_year
                sampling_days = range(0, days_in_period, 7)  # Weekly

            # Generate data for each sampling day
            for day_offset in sampling_days:
                current_date = end_date - timedelta(days=day_offset)
                days_ago = (today - current_date).days

                # Daily measurements
                # -----------------

                # Glucose (3x daily for all patients)
                for hour in [8, 13, 19]:
                    # Values differ by patient group
                    if patient_group == 0:  # Heart disease
                        base_glucose = 8.0  # Higher baseline
                        variation = 1.5  # Wider fluctuations
                    elif patient_group == 1:  # Normal
                        base_glucose = 5.5  # Normal baseline
                        variation = 0.5  # Narrower fluctuations
                    else:  # At risk
                        base_glucose = 6.5  # Slightly elevated
                        variation = 0.8  # Moderate fluctuations

                    # Heart disease slowly worsens, normal stays stable, at-risk slowly worsens
                    glucose_value = generate_biomarker_value(base_glucose * 10, variation * 10,
                                                             patient_group, days_ago, 5)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime(f"{hour}:00", "%H:%M").time(),
                        recorded_value=glucose_value,
                        element_id=glucose.element_id,
                        user_id=patient.patient_id
                    ))
                    total_measurements += 1

                # Weekly or bi-weekly measurements
                # --------------------------------

                # These measurements happen less frequently
                is_weekly_sample = day_offset % 7 == 0
                is_biweekly_sample = day_offset % 14 == 0

                # Weekly measurements
                if is_weekly_sample:
                    # Sodium
                    if patient_group == 0:  # Heart disease
                        sodium_base = 148  # Elevated
                        sodium_var = 5
                    elif patient_group == 1:  # Normal
                        sodium_base = 140  # Normal
                        sodium_var = 3
                    else:  # At risk
                        sodium_base = 142  # Slightly elevated
                        sodium_var = 4

                    sodium_value = generate_biomarker_value(sodium_base, sodium_var,
                                                            patient_group, days_ago, 3)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("10:30", "%H:%M").time(),
                        recorded_value=sodium_value,
                        element_id=sodium.element_id,
                        user_id=patient.patient_id
                    ))

                    # Potassium
                    if patient_group == 0:  # Heart disease
                        potassium_base = 45  # Borderline
                        potassium_var = 8
                    elif patient_group == 1:  # Normal
                        potassium_base = 42  # Normal
                        potassium_var = 5
                    else:  # At risk
                        potassium_base = 44  # Slightly off
                        potassium_var = 6

                    potassium_value = generate_biomarker_value(potassium_base, potassium_var,
                                                               patient_group, days_ago, 2)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("11:15", "%H:%M").time(),
                        recorded_value=potassium_value,
                        element_id=potassium.element_id,
                        user_id=patient.patient_id
                    ))

                    # Lactate
                    if patient_group == 0:  # Heart disease
                        lactate_base = 25  # Elevated
                        lactate_var = 8
                    elif patient_group == 1:  # Normal
                        lactate_base = 12  # Normal
                        lactate_var = 4
                    else:  # At risk
                        lactate_base = 17  # Slightly elevated
                        lactate_var = 5

                    lactate_value = generate_biomarker_value(lactate_base, lactate_var,
                                                             patient_group, days_ago, 5)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("14:45", "%H:%M").time(),
                        recorded_value=lactate_value,
                        element_id=lactate.element_id,
                        user_id=patient.patient_id
                    ))

                    # Cortisol
                    if patient_group == 0:  # Heart disease
                        cortisol_base = 300  # High stress
                        cortisol_var = 50
                    elif patient_group == 1:  # Normal
                        cortisol_base = 150  # Normal
                        cortisol_var = 30
                    else:  # At risk
                        cortisol_base = 230  # Slightly elevated
                        cortisol_var = 40

                    cortisol_value = generate_biomarker_value(cortisol_base, cortisol_var,
                                                              patient_group, days_ago, 10)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("08:30", "%H:%M").time(),
                        recorded_value=cortisol_value,
                        element_id=cortisol.element_id,
                        user_id=patient.patient_id
                    ))

                    # Apolipoprotein
                    if patient_group == 0:  # Heart disease
                        apo_base = 220  # High
                        apo_var = 20
                    elif patient_group == 1:  # Normal
                        apo_base = 130  # Normal
                        apo_var = 15
                    else:  # At risk
                        apo_base = 180  # Borderline high
                        apo_var = 18

                    apo_value = generate_biomarker_value(apo_base, apo_var,
                                                         patient_group, days_ago, 25)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("09:15", "%H:%M").time(),
                        recorded_value=apo_value,
                        element_id=apolipoprotein.element_id,
                        user_id=patient.patient_id
                    ))

                    total_measurements += 5

                # Bi-weekly measurements for specific cardiac markers
                if is_biweekly_sample:
                    # Troponin I
                    if patient_group == 0:  # Heart disease
                        troponin_base = 150  # Elevated
                        troponin_var = 50
                    elif patient_group == 1:  # Normal
                        troponin_base = 15  # Normal
                        troponin_var = 10
                    else:  # At risk
                        troponin_base = 35  # Borderline
                        troponin_var = 15

                    troponin_value = generate_biomarker_value(troponin_base, troponin_var,
                                                              patient_group, days_ago, 30)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("11:30", "%H:%M").time(),
                        recorded_value=troponin_value,
                        element_id=troponin.element_id,
                        user_id=patient.patient_id
                    ))

                    # BNP
                    if patient_group == 0:  # Heart disease
                        bnp_base = 280  # Elevated
                        bnp_var = 80
                    elif patient_group == 1:  # Normal
                        bnp_base = 50  # Normal
                        bnp_var = 20
                    else:  # At risk
                        bnp_base = 100  # Borderline
                        bnp_var = 30

                    bnp_value = generate_biomarker_value(bnp_base, bnp_var,
                                                         patient_group, days_ago, 40)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("12:00", "%H:%M").time(),
                        recorded_value=bnp_value,
                        element_id=bnp.element_id,
                        user_id=patient.patient_id
                    ))

                    # CRP
                    if patient_group == 0:  # Heart disease
                        crp_base = 70  # Inflammatory state
                        crp_var = 15
                    elif patient_group == 1:  # Normal
                        crp_base = 10  # Normal
                        crp_var = 5
                    else:  # At risk
                        crp_base = 35  # Slightly elevated
                        crp_var = 10

                    crp_value = generate_biomarker_value(crp_base, crp_var,
                                                         patient_group, days_ago, 15)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("12:45", "%H:%M").time(),
                        recorded_value=crp_value,
                        element_id=crp.element_id,
                        user_id=patient.patient_id
                    ))

                    # Homocysteine
                    if patient_group == 0:  # Heart disease
                        homo_base = 220  # Elevated
                        homo_var = 30
                    elif patient_group == 1:  # Normal
                        homo_base = 90  # Normal
                        homo_var = 20
                    else:  # At risk
                        homo_base = 160  # Borderline high
                        homo_var = 25

                    homo_value = generate_biomarker_value(homo_base, homo_var,
                                                          patient_group, days_ago, 20)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("13:30", "%H:%M").time(),
                        recorded_value=homo_value,
                        element_id=homocysteine.element_id,
                        user_id=patient.patient_id
                    ))

                    # HDL Cholesterol
                    if patient_group == 0:  # Heart disease
                        hdl_base = 80  # Low (bad)
                        hdl_var = 10
                    elif patient_group == 1:  # Normal
                        hdl_base = 150  # Healthy
                        hdl_var = 15
                    else:  # At risk
                        hdl_base = 100  # Borderline
                        hdl_var = 12

                    hdl_value = generate_biomarker_value(hdl_base, hdl_var,
                                                         patient_group, days_ago, 15)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("14:15", "%H:%M").time(),
                        recorded_value=hdl_value,
                        element_id=hdl.element_id,
                        user_id=patient.patient_id
                    ))

                    # LDL Cholesterol
                    if patient_group == 0:  # Heart disease
                        ldl_base = 420  # High (bad)
                        ldl_var = 40
                    elif patient_group == 1:  # Normal
                        ldl_base = 200  # Normal
                        ldl_var = 30
                    else:  # At risk
                        ldl_base = 330  # Borderline high
                        ldl_var = 35

                    ldl_value = generate_biomarker_value(ldl_base, ldl_var,
                                                         patient_group, days_ago, 30)

                    db.session.add(DeviceDataQuery(
                        date_logged=current_date,
                        time_stamp=datetime.strptime("14:30", "%H:%M").time(),
                        recorded_value=ldl_value,
                        element_id=ldl.element_id,
                        user_id=patient.patient_id
                    ))

                    total_measurements += 6

            # Commit every 1000 measurements to avoid memory issues
            if total_measurements % 1000 == 0:
                db.session.commit()
                print(f"Committed {total_measurements} measurements so far...")

    # Final commit
    db.session.commit()
    print(f"Created {total_measurements} device measurements for all patients across multiple time periods")


if __name__ == "__main__":
    with app.app_context():
        print("Starting database seeding...")

        # First, confirm dropping all existing data
        confirm = input("WARNING: This will DELETE ALL EXISTING DATA. Continue? (yes/no): ")
        if confirm.lower() != "yes":
            print("Database seeding cancelled.")
            sys.exit(0)

        # Drop all tables and recreate them
        from models import db

        print("Dropping all existing tables...")
        db.drop_all()
        print("Creating new tables...")
        db.create_all()
        print("Database reset completed")

        # Create users
        print("\nCreating users...")
        admin, patients = create_users()

        # Create reference data
        print("\nCreating reference data...")
        create_reference_data()

        # Create patient data
        print("\nCreating patient health data...")
        patient_profiles = create_patient_data(patients)

        # Create device measurements
        print("\nCreating device measurements...")
        create_device_data(patient_profiles)

        print("\nDatabase seeding completed!")
        print("\nLogin credentials:")
        print("Admin: admin@example.com / Admin123!")

        print("\nPatients with heart disease:")
        print("Patient 1: patient1@example.com / Patient1!")
        print("Patient 2: patient2@example.com / Patient2!")

        print("\nPatients with normal parameters:")
        print("Patient 3: patient3@example.com / Patient3!")
        print("Patient 4: patient4@example.com / Patient4!")

        print("\nPatients at risk of heart disease:")
        print("Patient 5: patient5@example.com / Patient5!")
        print("Patient 6: patient6@example.com / Patient6!")