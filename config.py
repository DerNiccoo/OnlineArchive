import os

class Config(object):
  SECRET_KEY = os.environ.get('SECRET_KEY') or 'debug-key-use-env'
  
  SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql:///feuerwehr'
  SQLALCHEMY_TRACK_MODIFICATIONS = False
  
  DROPZONE_UPLOAD_MULTIPLE = True
  DROPZONE_ALLOWED_FILE_CUSTOM = True
  DROPZONE_ALLOWED_FILE_TYPE = '.pdf, .jpg'
  DROPZONE_REDIRECT_VIEW = 'results'
  UPLOADED_IMG_DEST = os.getcwd() + '/app//img'