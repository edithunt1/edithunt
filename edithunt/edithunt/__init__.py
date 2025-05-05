from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from sqlalchemy import or_
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import requests
import base64
from edithunt.models import db

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edithunt.db'  # 또는 mysql+pymysql://user:pw@host/db
    db.init_app(app)
    login_manager.init_app(app)
    socketio = SocketIO(app)

    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'mov'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # models.py, forms.py에서 모델/폼 import

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(128), nullable=False)
        role = db.Column(db.String(20), nullable=False, default='freelancer')

    class Message(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        content = db.Column(db.Text)
        timestamp = db.Column(db.DateTime, server_default=db.func.now())
        is_read = db.Column(db.Boolean, default=False)  # 읽음 여부

    class Portfolio(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        freelancer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        content = db.Column(db.Text)

    class Payment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 프리랜서 id
        amount = db.Column(db.Integer)
        timestamp = db.Column(db.DateTime, server_default=db.func.now())
        description = db.Column(db.String(200))

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            if User.query.filter_by(email=email).first():
                flash('이미 존재하는 이메일입니다.', 'danger')
                return redirect(url_for('register'))
            user = User(email=email, password=password, role=role)
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
            return '로그인 실패'
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        # 본인 결제 내역(수익) 표시
        payments = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.timestamp.desc()).all()
        my_portfolio = Portfolio.query.filter_by(freelancer_id=current_user.id).first()
        return render_template('dashboard.html', payments=payments, my_portfolio=my_portfolio)

    @app.route('/messages')
    @login_required
    def messages_list():
        # 내가 주고받은 모든 메시지의 상대방 id 추출
        sent = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id)
        received = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id)
        user_ids = set([r[0] for r in sent] + [r[0] for r in received])
        user_ids.discard(current_user.id)  # 자기 자신 제외
        users = User.query.filter(User.id.in_(user_ids)).all()
        # 각 상대방별 마지막 메시지 가져오기
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

    # 템플릿에서 사용하려면 context_processor로 등록
    @app.context_processor
    def inject_unread_count():
        return dict(unread_count=get_unread_count())

    @app.route('/portfolio/register', methods=['GET', 'POST'])
    @login_required
    def portfolio_register():
        if request.method == 'POST':
            content = request.form['content']
            file = request.files.get('file')
            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # 결제 페이지로 이동(임시로 세션에 정보 저장)
            session['portfolio_content'] = content
            session['portfolio_filename'] = filename
            return redirect(url_for('pay_portfolio'))
        return render_template('portfolio_register.html')

    @app.route('/pay/portfolio', methods=['GET', 'POST'])
    @login_required
    def pay_portfolio():
        # 포트폴리오 등록비 고정(예: 10000원)
        amount = 10000
        if request.method == 'POST':
            # 실제 결제 연동(테스트용으로 바로 성공 처리)
            # 결제 성공 시 포트폴리오 등록
            content = session.pop('portfolio_content', None)
            filename = session.pop('portfolio_filename', None)
            if content:
                portfolio = Portfolio(content=content, freelancer_id=current_user.id)
                if filename:
                    portfolio.content += f'<br><a href="/static/uploads/{filename}" target="_blank">첨부파일</a>'
                db.session.add(portfolio)
                # 결제 내역 기록
                payment = Payment(user_id=current_user.id, amount=amount, description='포트폴리오 등록비')
                db.session.add(payment)
                db.session.commit()
                flash('포트폴리오가 결제와 함께 등록되었습니다!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('세션 만료. 다시 시도해주세요.', 'danger')
                return redirect(url_for('portfolio_register'))
        return render_template('pay_portfolio.html', amount=amount)

    @app.route('/portfolios')
    @login_required
    def portfolio_list():
        portfolios = Portfolio.query.all()
        return render_template('portfolio_list.html', portfolios=portfolios)

    @app.route('/portfolio/<int:portfolio_id>')
    @login_required
    def portfolio_detail(portfolio_id):
        portfolio = Portfolio.query.get_or_404(portfolio_id)
        freelancer = User.query.get(portfolio.freelancer_id)
        return render_template('portfolio_detail.html', portfolio=portfolio, freelancer=freelancer)

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
        # 프리랜서의 포트폴리오, 클라이언트의 프로젝트 등도 함께 보여줄 수 있음
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
        project_id = request.form.get('project_id')  # project_id도 받음

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
            # 결제 성공 시 프로젝트 활성화
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
        # Toss에서 결제 성공 시 호출
        paymentKey = request.args.get('paymentKey')
        orderId = request.args.get('orderId')
        amount = request.args.get('amount')
        # 결제 승인 처리(POST로 pay_confirm 호출)
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

    # 메시지 전송 시 실시간으로 알림 보내기 예시
    @socketio.on('send_message')
    def handle_send_message(data):
        # data: {'receiver_id': ..., 'content': ...}
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
        # 메시지 내역 조회 (양방향)
        msgs = Message.query.filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.receiver_id == user_id),
                (Message.sender_id == user_id) & (Message.receiver_id == current_user.id)
            )
        ).order_by(Message.timestamp.asc()).all()
        # 내가 받은 메시지 중 안 읽은 것 읽음 처리
        unread_msgs = Message.query.filter_by(sender_id=user_id, receiver_id=current_user.id, is_read=False).all()
        for m in unread_msgs:
            m.is_read = True
        db.session.commit()
        return render_template('messages.html', msgs=msgs, user_id=user_id)

    # 블루프린트 등록
    from edithunt.api import api_bp
    from edithunt.web import web_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(web_bp)

    return app

if __name__ == '__main__':
    print('Flask Edithunt 서버를 시작합니다!')
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
