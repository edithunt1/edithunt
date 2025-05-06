from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from sqlalchemy import or_
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import requests
import base64

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Web routes
@app.route('/')
def index():
    return render_template('index.html')

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
        user = User(email=email, password=password, role=role, nickname=nickname)
        db.session.add(user)
        db.session.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
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
    my_portfolio = Portfolio.query.filter_by(freelancer_id=current_user.id).first()
    return render_template('dashboard.html', payments=payments, my_portfolio=my_portfolio)

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
    users = User.query.all()
    portfolios = Portfolio.query.all()
    payments = Payment.query.all()
    return render_template('admin.html', users=users, portfolios=portfolios, payments=payments)

@app.route('/profile')
@login_required
def profile():
    my_portfolio = Portfolio.query.filter_by(freelancer_id=current_user.id).first()
    return render_template('profile.html', my_portfolio=my_portfolio)

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
        if email:
            current_user.email = email
        if password:
            current_user.password = password
        db.session.commit()
        flash('프로필이 수정되었습니다.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile_edit.html', user=current_user)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@socketio.on('send_message')
def handle_send_message(data):
    emit('receive_message', data, room=data['receiver_id'])

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def messages_detail(user_id):
    if request.method == 'POST':
        content = request.form['content']
        msg = Message(sender_id=current_user.id, receiver_id=user_id, content=content)
        db.session.add(msg)
        db.session.commit()
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        from sqlalchemy import text
        db.engine.execute(text('ALTER TABLE portfolio ADD COLUMN tags VARCHAR(255);'))
    print('Flask Edithunt 서버를 시작합니다!')
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True) 