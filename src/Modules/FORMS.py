from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email/Usuario', validators=[DataRequired()])
    passw = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    redirect_for = HiddenField()
    submit = SubmitField('Iniciar Sesión')

class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired()])
    passw = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField('Registrarse')

class ResetPasswordForm(FlaskForm):
    passw = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=8, max=128)])
    passw2 = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('passw')])
    token = HiddenField()
    submit = SubmitField('Cambiar Contraseña')

class EmailConfirmForm(FlaskForm):
    email = HiddenField()
    code = StringField('Código de Confirmación', validators=[DataRequired()])
    submit = SubmitField('Confirmar')

class UploadForm(FlaskForm):
    file = MultipleFileField('Archivos', validators=[DataRequired()])
    submit = SubmitField('Subir')

class EmailRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Enviar')