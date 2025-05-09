from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from .models import User

class LoginForm(FlaskForm):
    email = StringField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    remember = BooleanField('로그인 상태 유지')
    submit = SubmitField('로그인')

class RegistrationForm(FlaskForm):
    username = StringField('사용자 이름', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('회원가입')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('이미 사용 중인 사용자 이름입니다.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('이미 사용 중인 이메일입니다.')

class PortfolioForm(FlaskForm):
    title = StringField('제목', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('설명', validators=[DataRequired()])
    image_url = StringField('이미지 URL', validators=[DataRequired()])
    submit = SubmitField('저장')

class MessageForm(FlaskForm):
    content = TextAreaField('메시지', validators=[DataRequired()])
    submit = SubmitField('전송') 