from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def notify_user(user_id, content, type='general', link=None):
    """
    사용자에게 알림을 보내는 함수
    
    Args:
        user_id (int): 알림을 받을 사용자의 ID
        content (str): 알림 내용
        type (str): 알림 유형 ('message', 'project', 'portfolio', 'general')
        link (str, optional): 알림 클릭 시 이동할 링크
    """
    try:
        notification = Notification(
            user_id=user_id,
            content=content,
            type=type,
            link=link,
            is_read=False,
            created_at=datetime.utcnow()
        )
        db.session.add(notification)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"알림 전송 실패: {str(e)}")
        return False 