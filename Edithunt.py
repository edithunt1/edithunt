from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from sqlalchemy import or_, inspect
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room
import requests
import base64
import secrets
from flask_mail import Message as MailMessage, Mail
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from sqlalchemy import text
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edithunt.db'
app.config['MAIL_SERVER'] = ''  # ex: 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''  # your email
app.config['MAIL_PASSWORD'] = ''  # your password
app.config['MAIL_DEFAULT_SENDER'] = ''
db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app)
mail = Mail(app)
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'mov'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='freelancer')
    nickname = db.Column(db.String(32), unique=True, nullable=False)  # 닉네임(중복 불가)
    profile_image = db.Column(db.String(256), default='default_profile.jpg')  # 프로필 이미지 필드 추가
    is_verified = db.Column(db.Boolean, default=False)  # 이메일 인증 여부
    verify_token = db.Column(db.String(128), nullable=True)  # 이메일 인증 토큰
    reset_token = db.Column(db.String(128), nullable=True)  # 비밀번호 재설정 토큰
    is_admin = db.Column(db.Boolean, default=False)  # 관리자 여부

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    freelancer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    price = db.Column(db.String(128))  # 금액(자유 입력)
    category = db.Column(db.String(64))  # 카테고리
    thumbnail = db.Column(db.String(256))  # 썸네일 파일 경로
    files = db.Column(db.Text)  # 첨부파일 목록(여러 개, 콤마로 구분)
    tags = db.Column(db.String(255))  # 쉼표로 구분된 태그 문자열

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    description = db.Column(db.String(200))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 알림 대상
    type = db.Column(db.String(32), nullable=False)  # 알림 종류 (message, payment 등)
    message = db.Column(db.String(256), nullable=False)  # 알림 내용
    is_read = db.Column(db.Boolean, default=False)  # 읽음 여부
    timestamp = db.Column(db.DateTime, server_default=db.func.now())  # 생성 시각

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(256), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Web routes
@app.route('/')
def index():
    return render_template('index.html')

def send_verification_email(user_email, token):
    # 실제 서비스에서는 Flask-Mail 등으로 메일 발송
    # 여기서는 print로 대체
    verify_url = url_for('verify_email', token=token, _external=True)
    print(f"[이메일 인증] {user_email} → 인증 링크: {verify_url}")
    # 실제 메일 발송 예시:
    # msg = MailMessage('EditHunt 이메일 인증', recipients=[user_email])
    # msg.body = f'아래 링크를 클릭해 이메일 인증을 완료하세요:\n{verify_url}'
    # mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        nickname = request.form['nickname']
        if User.query.filter_by(email=email).first():
            flash('이미 존재하는 이메일입니다.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(nickname=nickname).first():
            flash('이미 존재하는 닉네임입니다.', 'danger')
            return redirect(url_for('register'))
        verify_token = secrets.token_urlsafe(32)
        hashed_pw = generate_password_hash(password)
        user = User(email=email, password=hashed_pw, role=role, nickname=nickname, is_verified=False, verify_token=verify_token)
        db.session.add(user)
        db.session.commit()
        send_verification_email(email, verify_token)
        flash('회원가입이 완료되었습니다. 이메일 인증을 완료해 주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verify_token=token).first()
    if user:
        user.is_verified = True
        user.verify_token = None
        db.session.commit()
        flash('이메일 인증이 완료되었습니다! 이제 로그인할 수 있습니다.', 'success')
        return redirect(url_for('login'))
    else:
        flash('유효하지 않은 인증 링크입니다.', 'danger')
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('이메일 인증이 필요합니다. 메일함을 확인해 주세요.', 'danger')
                return render_template('login.html')
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('이메일 또는 비밀번호를 확인해 주세요.', 'danger')
        return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    payments = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.timestamp.desc()).all()
    my_portfolios = Portfolio.query.filter_by(freelancer_id=current_user.id).all()
    my_payments_count = len(payments)
    my_payments_total = sum([p.amount for p in payments])
    my_portfolio_count = len(my_portfolios)
    return render_template('dashboard.html', payments=payments, my_portfolios=my_portfolios,
        my_payments_count=my_payments_count, my_payments_total=my_payments_total, my_portfolio_count=my_portfolio_count)

@app.route('/messages')
@login_required
def messages_list():
    sent = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id)
    received = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id)
    user_ids = set([r[0] for r in sent] + [r[0] for r in received])
    user_ids.discard(current_user.id)
    users = User.query.filter(User.id.in_(user_ids)).all()
    last_msgs = {}
    for u in users:
        msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == u.id)) |
            ((Message.sender_id == u.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        last_msgs[u.id] = msg
    return render_template('messages_list.html', users=users, last_msgs=last_msgs)

def get_unread_count():
    if current_user.is_authenticated:
        return Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    return 0

@app.context_processor
def inject_unread_count():
    return dict(unread_count=get_unread_count())

@app.route('/portfolio/register', methods=['GET', 'POST'])
@login_required
def portfolio_register():
    if request.method == 'POST':
        content = request.form['content']
        price = request.form.get('price', '').strip()
        category = request.form.get('category', '').strip()
        files = request.files.getlist('file')  # 여러 첨부파일
        thumbnail_file = request.files.get('thumbnail')  # 썸네일 파일
        tags = request.form.get('tags', '')
        filenames = []
        thumbnail_filename = None
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filenames.append(filename)
        if thumbnail_file and allowed_file(thumbnail_file.filename):
            thumbnail_filename = secure_filename(thumbnail_file.filename)
            thumbnail_file.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename))
        portfolio = Portfolio(content=content, freelancer_id=current_user.id, price=price, category=category, thumbnail=thumbnail_filename, files=','.join(filenames), tags=tags)
        db.session.add(portfolio)
        db.session.commit()
        flash('포트폴리오가 등록되었습니다!', 'success')
        return redirect(url_for('portfolio_detail', portfolio_id=portfolio.id))
    return render_template('portfolio_register.html')

@app.route('/portfolios')
def portfolio_list():
    query = request.args.get('query', '').strip()
    portfolios = Portfolio.query
    if query:
        user_ids = [u.id for u in User.query.filter(User.email.contains(query)).all()]
        portfolios = portfolios.filter(
            (Portfolio.content.contains(query)) |
            (Portfolio.freelancer_id.in_(user_ids)) |
            (Portfolio.tags.contains(query))
        )
    portfolios = portfolios.all()
    # 프리랜서 id -> User 객체 dict
    user_ids = list(set([p.freelancer_id for p in portfolios]))
    users = User.query.filter(User.id.in_(user_ids)).all()
    users_dict = {u.id: u for u in users}
    payments = set()
    if current_user.is_authenticated:
        payments = set([pay.description.split(':')[-1].strip() for pay in Payment.query.filter_by(user_id=current_user.id).all() if pay.description and '포트폴리오 결제:' in pay.description])
        payments = set([int(pid) for pid in payments if pid.isdigit()])
    return render_template('portfolio_list.html', portfolios=portfolios, users_dict=users_dict, payments=payments)

@app.route('/portfolio/<int:portfolio_id>')
def portfolio_detail(portfolio_id):
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    freelancer = User.query.get(portfolio.freelancer_id)
    file_list = portfolio.files.split(',') if portfolio.files else []
    payments = set()
    if current_user.is_authenticated:
        payments = set([pay.description.split(':')[-1].strip() for pay in Payment.query.filter_by(user_id=current_user.id).all() if pay.description and '포트폴리오 결제:' in pay.description])
        payments = set([int(pid) for pid in payments if pid.isdigit()])
    return render_template('portfolio_detail.html', portfolio=portfolio, freelancer=freelancer, file_list=file_list, payments=payments)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('관리자만 접근 가능합니다.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    portfolios = Portfolio.query.all()
    payments = Payment.query.all()
    # 통계 데이터 계산
    from datetime import datetime, timedelta
    total_users = len(users)
    total_portfolios = len(portfolios)
    total_payments = len(payments)
    total_amount = sum([p.amount for p in payments])
    # 최근 7일 결제 추이
    today = datetime.utcnow().date()
    last7 = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    payments_by_day = {d:0 for d in last7}
    for p in payments:
        if p.timestamp:
            d = p.timestamp.date()
            if d in payments_by_day:
                payments_by_day[d] += p.amount
    payments_chart_labels = [d.strftime('%m-%d') for d in last7]
    payments_chart_data = [payments_by_day[d] for d in last7]
    return render_template('admin.html', users=users, portfolios=portfolios, payments=payments,
        total_users=total_users, total_portfolios=total_portfolios, total_payments=total_payments, total_amount=total_amount,
        payments_chart_labels=payments_chart_labels, payments_chart_data=payments_chart_data)

@app.route('/profile')
@login_required
def profile():
    my_portfolio = Portfolio.query.filter_by(freelancer_id=current_user.id).first()
    return render_template('profile.html', my_portfolio=my_portfolio, user=current_user)

@app.route('/pay/<int:project_id>', methods=['GET'])
@login_required
def pay(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('pay.html', project=project, client_key='테스트_클라이언트키')

@app.route('/pay/confirm', methods=['POST'])
@login_required
def pay_confirm():
    paymentKey = request.form['paymentKey']
    orderId = request.form['orderId']
    amount = request.form['amount']
    project_id = request.form.get('project_id')
    secret_key = '테스트_시크릿키'
    auth = base64.b64encode(f"{secret_key}:".encode('utf-8')).decode('utf-8')
    headers = {
        'Authorization': f'Basic {auth}',
        'Content-Type': 'application/json'
    }
    data = {
        'paymentKey': paymentKey,
        'orderId': orderId,
        'amount': int(amount)
    }
    response = requests.post(
        'https://api.tosspayments.com/v1/payments/confirm',
        headers=headers,
        json=data
    )
    if response.status_code == 200:
        if project_id:
            project = Project.query.get(int(project_id))
            if project:
                project.status = 'active'
                db.session.commit()
        flash('결제가 성공적으로 완료되었습니다!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('결제 실패: ' + response.json().get('message', ''), 'danger')
        return redirect(url_for('dashboard'))

@app.route('/pay/success')
def pay_success():
    paymentKey = request.args.get('paymentKey')
    orderId = request.args.get('orderId')
    amount = request.args.get('amount')
    return render_template('pay_success.html', paymentKey=paymentKey, orderId=orderId, amount=amount)

@app.route('/pay/fail')
def pay_fail():
    message = request.args.get('message', '결제 실패')
    return render_template('pay_fail.html', message=message)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nickname = request.form['nickname']
        
        # 프로필 이미지 처리
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                # 기존 프로필 이미지가 기본 이미지가 아닌 경우 삭제
                if current_user.profile_image != 'default_profile.jpg':
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_image))
                    except:
                        pass
                
                # 새 이미지 저장
                filename = secure_filename(f"profile_{current_user.id}_{int(time.time())}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_image = filename
        
        if email:
            current_user.email = email
        if password:
            current_user.password = generate_password_hash(password)
        if nickname:
            current_user.nickname = nickname
            
        db.session.commit()
        flash('프로필이 수정되었습니다.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile_edit.html', user=current_user)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@socketio.on('send_message')
def handle_send_message(data):
    emit('receive_message', data, room=data['receiver_id'])

@socketio.on('join')
def on_join(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(str(user_id))

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def messages_detail(user_id):
    if request.method == 'POST':
        content = request.form['content']
        msg = Message(sender_id=current_user.id, receiver_id=user_id, content=content)
        db.session.add(msg)
        db.session.commit()
        # 메시지 수신자에게 알림 생성
        notif = Notification(user_id=user_id, type='message', message=f'{current_user.nickname}님이 새 메시지를 보냈습니다.', is_read=False)
        db.session.add(notif)
        db.session.commit()
        # 실시간 알림 전송
        socketio.emit('send_notification', {
            'type': 'message',
            'message': notif.message,
            'timestamp': notif.timestamp.isoformat(),
            'notif_id': notif.id
        }, room=str(user_id))
        return redirect(url_for('messages_detail', user_id=user_id))
    msgs = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.receiver_id == user_id),
            (Message.sender_id == user_id) & (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()
    unread_msgs = Message.query.filter_by(sender_id=user_id, receiver_id=current_user.id, is_read=False).all()
    for m in unread_msgs:
        m.is_read = True
    db.session.commit()
    return render_template('messages.html', msgs=msgs, user_id=user_id)

# API endpoints (REST)
@app.route('/api/users', methods=['GET'])
def api_get_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'email': u.email} for u in users])

@app.route('/api/users/<int:user_id>', methods=['GET'])
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({'id': user.id, 'email': user.email})

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 409
    user = User(email=email, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email, password=password).first()
    if user:
        login_user(user)
        return jsonify({'message': 'Login successful'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/portfolios', methods=['GET'])
def api_portfolio_list():
    portfolios = Portfolio.query.all()
    return jsonify([
        {'id': p.id, 'freelancer_id': p.freelancer_id, 'content': p.content}
        for p in portfolios
    ])

@app.route('/api/portfolios', methods=['POST'])
@login_required
def api_portfolio_create():
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'error': 'Content required'}), 400
    portfolio = Portfolio(content=content, freelancer_id=current_user.id)
    db.session.add(portfolio)
    db.session.commit()
    return jsonify({'message': 'Portfolio created', 'id': portfolio.id})

@app.route('/api/messages', methods=['GET'])
@login_required
def api_messages_list():
    messages = Message.query.filter((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)).all()
    return jsonify([
        {'id': m.id, 'sender_id': m.sender_id, 'receiver_id': m.receiver_id, 'content': m.content, 'timestamp': m.timestamp.isoformat()}
        for m in messages
    ])

@app.route('/api/messages', methods=['POST'])
@login_required
def api_send_message():
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    if not receiver_id or not content:
        return jsonify({'error': 'receiver_id and content required'}), 400
    msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    # 메시지 수신자에게 알림 생성
    notif = Notification(user_id=receiver_id, type='message', message=f'{current_user.nickname}님이 새 메시지를 보냈습니다.', is_read=False)
    db.session.add(notif)
    db.session.commit()
    # 실시간 알림 전송
    socketio.emit('send_notification', {
        'type': 'message',
        'message': notif.message,
        'timestamp': notif.timestamp.isoformat(),
        'notif_id': notif.id
    }, room=str(receiver_id))
    return jsonify({'message': 'Message sent', 'id': msg.id})

@app.route('/pay/portfolio/<int:portfolio_id>', methods=['GET', 'POST'])
@login_required
def pay_portfolio_detail(portfolio_id):
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    amount = portfolio.price or 10000
    if request.method == 'POST':
        # 실제 결제 연동 대신 테스트용으로 바로 성공 처리
        payment = Payment(user_id=current_user.id, amount=amount, description=f'포트폴리오 결제: {portfolio.id}')
        db.session.add(payment)
        db.session.commit()
        # 결제 성공 시, 구매자와 프리랜서 간 메시지방(최초 메시지) 자동 생성
        freelancer_id = portfolio.freelancer_id
        buyer_id = current_user.id
        # 이미 메시지 내역이 없으면 최초 메시지 생성
        existing = Message.query.filter(
            ((Message.sender_id == buyer_id) & (Message.receiver_id == freelancer_id)) |
            ((Message.sender_id == freelancer_id) & (Message.receiver_id == buyer_id))
        ).first()
        if not existing:
            msg = Message(sender_id=buyer_id, receiver_id=freelancer_id, content='포트폴리오 구매 후 자동 생성된 대화방입니다.')
            db.session.add(msg)
            db.session.commit()
        flash('포트폴리오 결제가 완료되었습니다! 프리랜서와 바로 대화할 수 있습니다.', 'success')
        return redirect(url_for('messages_detail', user_id=freelancer_id))
    return render_template('pay_portfolio_detail.html', portfolio=portfolio, amount=amount)

@app.route('/pay/portfolio/success/<int:portfolio_id>')
@login_required
def pay_portfolio_success(portfolio_id):
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    return render_template('pay_portfolio_success.html', portfolio=portfolio)

@app.route('/pay/portfolio/fail/<int:portfolio_id>')
@login_required
def pay_portfolio_fail(portfolio_id):
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    return render_template('pay_portfolio_fail.html', portfolio=portfolio)

@app.template_filter('format_number')
def format_number(value):
    try:
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return value

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            import secrets
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            db.session.commit()
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            print(f"[비밀번호 재설정] {email} → 링크: {reset_url}")
            # 실제 메일 발송 예시:
            # msg = MailMessage('EditHunt 비밀번호 재설정', recipients=[email])
            # msg.body = f'아래 링크를 클릭해 비밀번호를 재설정하세요:\n{reset_url}'
            # mail.send(msg)
            flash('비밀번호 재설정 링크가 이메일로 발송되었습니다.', 'success')
            return redirect(url_for('login'))
        else:
            flash('해당 이메일로 가입된 계정이 없습니다.', 'danger')
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('유효하지 않은 비밀번호 재설정 링크입니다.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['password']
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        db.session.commit()
        flash('비밀번호가 성공적으로 변경되었습니다! 로그인해 주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def notification_read(notif_id):
    notif = Notification.query.filter_by(id=notif_id, user_id=current_user.id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.route('/faq')
def faq_list():
    faqs = FAQ.query.filter_by(is_active=True).order_by(FAQ.order.asc(), FAQ.id.asc()).all()
    return render_template('faq.html', faqs=faqs)

@app.route('/robots.txt')
def robots_txt():
    content = 'User-agent: *\nAllow: /\nSitemap: ' + url_for('sitemap_xml', _external=True)
    return Response(content, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    from datetime import datetime
    pages = [
        url_for('index', _external=True),
        url_for('portfolio_list', _external=True),
        url_for('faq_list', _external=True),
        url_for('login', _external=True),
        url_for('register', _external=True),
    ]
    # 포트폴리오 상세
    for p in Portfolio.query.all():
        pages.append(url_for('portfolio_detail', portfolio_id=p.id, _external=True))
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url><loc>{page}</loc><lastmod>{datetime.utcnow().date()}</lastmod></url>\n'
    xml += '</urlset>'
    return Response(xml, mimetype='application/xml')

@app.route('/portfolio/delete/<int:portfolio_id>', methods=['POST'])
@login_required
def portfolio_delete(portfolio_id):
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    if portfolio.freelancer_id != current_user.id and not current_user.is_admin:
        flash('본인 소유의 포트폴리오만 삭제할 수 있습니다.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(portfolio)
    db.session.commit()
    flash('포트폴리오가 삭제되었습니다.', 'success')
    return redirect(url_for('dashboard'))

# NICE PG 결제 관련 설정
NICE_PG_MID = "nicepg_mid"  # 나이스페이먼츠 상점 ID
NICE_PG_KEY = "nicepg_key"  # 나이스페이먼츠 키
NICE_PG_RETURN_URL = "http://your-domain.com/pay/portfolio/complete"  # 결제 완료 후 리턴 URL

@app.route('/pay/portfolio', methods=['GET', 'POST'])
@login_required
def pay_portfolio():
    if request.method == 'POST':
        amount = request.form.get('amount')
        order_id = request.form.get('order_id')
        payment_method = request.form.get('payment_method')
        
        # 나이스페이먼츠 결제 요청 데이터 생성
        payment_data = {
            'MID': NICE_PG_MID,
            'Moid': order_id,
            'GoodsName': '포트폴리오 등록',
            'Amt': amount,
            'BuyerName': current_user.username,
            'BuyerEmail': current_user.email,
            'ReturnURL': NICE_PG_RETURN_URL,
            'PayMethod': payment_method
        }
        
        # 결제 요청 처리
        try:
            # 나이스페이먼츠 결제창 호출
            return render_template('nice_payment.html', payment_data=payment_data)
        except Exception as e:
            flash('결제 처리 중 오류가 발생했습니다.', 'danger')
            return redirect(url_for('portfolio_register'))
    
    # GET 요청 처리 (결제 페이지 표시)
    amount = 10000  # 포트폴리오 등록 비용
    order_id = f"EDITHUNT-{int(time.time())}"
    return render_template('pay_portfolio.html', amount=amount, order_id=order_id)

@app.route('/pay/portfolio/complete', methods=['POST'])
@login_required
def pay_portfolio_complete():
    # 나이스페이먼츠 결제 완료 처리
    result_code = request.form.get('ResultCode')
    result_msg = request.form.get('ResultMsg')
    order_id = request.form.get('Moid')
    amount = request.form.get('Amt')
    
    if result_code == '0000':  # 결제 성공
        # 결제 내역 저장
        payment = Payment(
            user_id=current_user.id,
            amount=int(amount),
            description='포트폴리오 등록비',
            payment_id=order_id
        )
        db.session.add(payment)
        
        # 포트폴리오 등록 처리
        portfolio_content = session.pop('portfolio_content', None)
        if portfolio_content:
            portfolio = Portfolio(
                content=portfolio_content,
                freelancer_id=current_user.id
            )
            db.session.add(portfolio)
            db.session.commit()
            
            flash('포트폴리오가 성공적으로 등록되었습니다!', 'success')
            return redirect(url_for('dashboard'))
    else:
        flash(f'결제 실패: {result_msg}', 'danger')
        return redirect(url_for('portfolio_register'))

if __name__ == '__main__':
    with app.app_context():
        # 데이터베이스 마이그레이션
        inspector = inspect(db.engine)
        if 'user' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            # 필요한 컬럼들 추가
            missing_columns = {
                'is_verified': 'BOOLEAN DEFAULT FALSE',
                'verify_token': 'VARCHAR(128)',
                'reset_token': 'VARCHAR(128)',
                'is_admin': 'BOOLEAN DEFAULT FALSE'
            }
            
            for col_name, col_type in missing_columns.items():
                if col_name not in columns:
                    try:
                        db.session.execute(text(f'ALTER TABLE user ADD COLUMN {col_name} {col_type}'))
                        db.session.commit()
                        print(f"{col_name} 컬럼이 추가되었습니다.")
                    except Exception as e:
                        print(f"{col_name} 컬럼 추가 실패:", e)
        else:
            # 테이블이 없는 경우 새로 생성
            db.create_all()
        
        # 기본 관리자 계정 생성
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                nickname='Admin',
                is_verified=True,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print('기본 관리자 계정이 생성되었습니다.')
        
        print('Flask Edithunt 서버를 시작합니다!')
        port = int(os.environ.get('PORT', 10000))
        app.run(host='0.0.0.0', port=port, debug=True) 