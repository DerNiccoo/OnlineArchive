from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_dropzone import Dropzone
from flask_uploads import UploadSet, configure_uploads, patch_request_class


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)

dropzone = Dropzone(app)
ALLOWED_EXTENSIONS = ('pdf', 'jpg', 'jpeg')
img_upload = UploadSet('img', extensions = ALLOWED_EXTENSIONS)
configure_uploads(app, img_upload)
patch_request_class(app)

from app import routes, models