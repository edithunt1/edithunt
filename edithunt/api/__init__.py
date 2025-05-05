from flask import Blueprint, jsonify, request, session
from edithunt.models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

api_bp = Blueprint('api', __name__)

@api_bp.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'email': u.email} for u in users])

@api_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({'id': user.id, 'email': user.email})

@api_bp.route('/register', methods=['POST'])
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

@api_bp.route('/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email, password=password).first()
    if user:
        login_user(user)
        return jsonify({'message': 'Login successful'})
    return jsonify({'error': 'Invalid credentials'}), 401

# 포트폴리오 예시 (list/create)
@api_bp.route('/portfolios', methods=['GET'])
def api_portfolio_list():
    from edithunt import create_app
    app = create_app()
    with app.app_context():
        Portfolio = db.Model._decl_class_registry.get('Portfolio')
        portfolios = Portfolio.query.all()
        return jsonify([
            {'id': p.id, 'freelancer_id': p.freelancer_id, 'content': p.content}
            for p in portfolios
        ])

@api_bp.route('/portfolios', methods=['POST'])
@login_required
def api_portfolio_create():
    from edithunt import create_app
    app = create_app()
    with app.app_context():
        Portfolio = db.Model._decl_class_registry.get('Portfolio')
        data = request.get_json()
        content = data.get('content')
        if not content:
            return jsonify({'error': 'Content required'}), 400
        portfolio = Portfolio(content=content, freelancer_id=current_user.id)
        db.session.add(portfolio)
        db.session.commit()
        return jsonify({'message': 'Portfolio created', 'id': portfolio.id})

# 메시지 예시 (list/send)
@api_bp.route('/messages', methods=['GET'])
@login_required
def api_messages_list():
    from edithunt import create_app
    app = create_app()
    with app.app_context():
        Message = db.Model._decl_class_registry.get('Message')
        messages = Message.query.filter((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)).all()
        return jsonify([
            {'id': m.id, 'sender_id': m.sender_id, 'receiver_id': m.receiver_id, 'content': m.content, 'timestamp': m.timestamp.isoformat()}
            for m in messages
        ])

@api_bp.route('/messages', methods=['POST'])
@login_required
def api_send_message():
    from edithunt import create_app
    app = create_app()
    with app.app_context():
        Message = db.Model._decl_class_registry.get('Message')
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        if not receiver_id or not content:
            return jsonify({'error': 'receiver_id and content required'}), 400
        msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return jsonify({'message': 'Message sent', 'id': msg.id}) 