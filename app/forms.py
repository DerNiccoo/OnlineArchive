from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import Account, AccountQuery

class RegistrationForm(FlaskForm):
  username = StringField('Nutzername', validators=[DataRequired()])
  password = StringField('Passwort', validators=[DataRequired()])
  submit = SubmitField('Registrieren')

  def validate_username(self, username):
    user = AccountQuery.get_User(username.data)
    if user is not None:
        raise ValidationError('Nutzername bereits in Verwendung.')

class ChangePasswordForm(FlaskForm):
  old_password = PasswordField('Altes Passwort', validators=[DataRequired()])
  new_password = PasswordField('Neues Passwort', validators=[DataRequired()])
  new_password_repeat = PasswordField('Neues Passwort wiederholen', validators=[DataRequired(), EqualTo('new_password', message='Passwörter müssen Übereinstimmen.')])
  submit = SubmitField('Ändern')

  def validate_old_password(self, old_password):
    user = AccountQuery.get_User(self.username)
    if user is None:
      raise ValidationError('Falscher Benutzer, bitte an einen Admin wenden.')

    if not user.check_password(old_password.data):
      raise ValidationError('Das eingegebene Passwort stimmt nicht mit dem aktuellen überein.')

  def validate_new_password(self, new_password):
    if self.old_password.data == new_password.data:
      raise ValidationError('Das neue Passwort darf nicht mit dem alten übereinstimmen.')