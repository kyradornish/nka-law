import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://kyra:ladies1271@localhost:5433/nza_law'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

