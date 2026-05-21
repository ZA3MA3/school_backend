import os
import pickle
import logging
from django.apps import AppConfig

logger = logging.getLogger(__name__)

# Global variables to store loaded model and artifacts
model = None
scaler = None
label_encoder = None
feature_names = None


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        global model, scaler, label_encoder, feature_names
        
        logger.info("Loading ML model artifacts...")
        
        # Get the path to the models directory
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        
        # Load the Keras model
        try:
            from tensorflow import keras
            model_path = os.path.join(models_dir, 'neural_network_model.keras')
            model = keras.models.load_model(model_path)
            logger.info(f"Loaded Keras model from {model_path}")
        except Exception as e:
            logger.error(f"Error loading Keras model: {e}")
            model = None
        
        # Load the scaler
        try:
            import joblib
            scaler_path = os.path.join(models_dir, 'scaler.pkl')
            scaler = joblib.load(scaler_path)
            logger.info(f"Loaded scaler from {scaler_path}")
        except Exception as e:
            logger.error(f"Error loading scaler: {e}")
            scaler = None
        
        # Load the label encoder
        try:
            import joblib
            label_encoder_path = os.path.join(models_dir, 'label_encoder.pkl')
            label_encoder = joblib.load(label_encoder_path)
            logger.info(f"Loaded label encoder from {label_encoder_path}")
        except Exception as e:
            logger.error(f"Error loading label encoder: {e}")
            label_encoder = None
        
        # Load feature names
        try:
            feature_names_path = os.path.join(models_dir, 'feature_names.pkl')
            with open(feature_names_path, 'rb') as f:
                feature_names = pickle.load(f)
            logger.info(f"Loaded feature names from {feature_names_path}")
        except Exception as e:
            logger.error(f"Error loading feature names: {e}")
            feature_names = None
        
        logger.info("ML model artifacts loaded successfully")


def predict_student_dropout(student_id):
    """
    Predict whether a student will dropout or graduate.
    Returns dict with prediction results.
    """
    from django.db import connection
    from .models import StudentProfile, Attendance, ExerciseSubmission, Exercise, Skill
    
    global model, scaler, label_encoder, feature_names
    
    logger.info(f"Starting prediction for student {student_id}")
    
    if model is None or scaler is None or label_encoder is None or feature_names is None:
        logger.error("Model artifacts not loaded")
        raise Exception("Model or artifacts not loaded")
    
    # Get student
    try:
        student = StudentProfile.objects.get(pk=student_id)
    except StudentProfile.DoesNotExist:
        logger.error(f"Student {student_id} not found")
        raise Exception(f"Student with id {student_id} not found")
    
    student_name = student.get_full_name
    logger.info(f"Student name: {student_name}")
    
    # Calculate the 6 real features from database
    
    # 1. total_absences - count of attendance records where student was absent
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT COUNT(*) FROM attendance 
            WHERE student_id = %s AND status = 'ABSENT'
        """, [student_id])
        total_absences = cursor.fetchone()[0]
    
    # 2. absence_rate - total_absences / 60, capped at 1.0
    absence_rate = min(total_absences / 60, 1.0)
    
    # 3. exercises_completed - count of submissions for this student
    exercises_completed = ExerciseSubmission.objects.filter(student_id=student_id).count()
    
    # 4. exercise_completion_rate - exercises_completed / 100, capped at 1.0
    exercise_completion_rate = min(exercises_completed / 100, 1.0)
    
    # 5. critical_skill_completion_rate - exercises with skill_importance=3 where student submitted
    total_critical_exercises = Exercise.objects.filter(
        skills__skill_importance=3
    ).distinct().count()
    
    if total_critical_exercises > 0:
        # Count of critical exercises where student has submitted
        critical_completed = ExerciseSubmission.objects.filter(
            student_id=student_id,
            exercise__skills__skill_importance=3
        ).distinct().count()
        critical_skill_completion_rate = critical_completed / total_critical_exercises
    else:
        critical_skill_completion_rate = 0.0
    
    # 6. total_critical_skills_missed - exercises with skill_importance=3 where student has NO submission
    if total_critical_exercises > 0:
        critical_completed = ExerciseSubmission.objects.filter(
            student_id=student_id,
            exercise__skills__skill_importance=3
        ).distinct().count()
        total_critical_skills_missed = total_critical_exercises - critical_completed
    else:
        total_critical_skills_missed = 0
    
    # Get student fields for prediction
    # Gender: 1 for male, 0 for female (default to 1 if not set)
    gender = 1 if student.gender is None else (1 if student.gender else 0)
    # Age at enrollment (default to 20 if not set)
    age_at_enrollment = student.enrollment_age if student.enrollment_age else 20
    # Scholarship holder: 1 for yes, 0 for no (default to 0 if not set)
    scholarship_holder = 1 if student.scholarship_holder else 0
    
    # Build feature dictionary with the 9 features in exact order
    feature_values = {
        'Gender': float(gender),
        'Age at enrollment': float(age_at_enrollment),
        'Scholarship holder': float(scholarship_holder),
        'total_absences': total_absences,
        'absence_rate': absence_rate,
        'exercises_completed': exercises_completed,
        'exercise_completion_rate': exercise_completion_rate,
        'critical_skill_completion_rate': critical_skill_completion_rate,
        'total_critical_skills_missed': total_critical_skills_missed,
    }
    
    logger.info(f"Feature values: {feature_values}")
    
    # Create DataFrame with exact feature order
    import pandas as pd
    df = pd.DataFrame([feature_values])[feature_names]
    logger.info(f"DataFrame columns: {df.columns.tolist()}")
    logger.info(f"DataFrame values: {df.values}")
    
    # Apply scaler
    scaled_data = scaler.transform(df)
    logger.info(f"Scaled data: {scaled_data}")
    
    # Predict
    prediction_prob = model.predict(scaled_data, verbose=0)[0][0]
    
    # Threshold at 0.5
    prediction_label = "Graduate" if prediction_prob >= 0.5 else "Dropout"
    
    # Get string label from encoder
    prediction_encoded = 1 if prediction_prob >= 0.5 else 0
    try:
        prediction_label = label_encoder.inverse_transform([prediction_encoded])[0]
    except:
        pass
    
    # Return results
    return {
        'student_id': student_id,
        'student_name': student_name,
        'prediction': prediction_label,
        'confidence': float(prediction_prob) if prediction_prob >= 0.5 else float(1 - prediction_prob),
        'features_used': {
            'gender': gender,
            'age_at_enrollment': age_at_enrollment,
            'scholarship_holder': scholarship_holder,
            'total_absences': total_absences,
            'absence_rate': round(absence_rate, 4),
            'exercises_completed': exercises_completed,
            'exercise_completion_rate': round(exercise_completion_rate, 2),
            'critical_skill_completion_rate': round(critical_skill_completion_rate, 2),
            'total_critical_skills_missed': total_critical_skills_missed
        }
    }