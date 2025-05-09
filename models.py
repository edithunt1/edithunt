class Notification(db.Model):
    """알림 모델"""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(20), nullable=False, default='general')  # message, project, portfolio, general
    link = db.Column(db.String(200))  # 알림 클릭 시 이동할 링크
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # 관계 설정
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f'<Notification {self.id}: {self.content[:20]}...>' 