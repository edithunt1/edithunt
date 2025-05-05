from edithunt import create_app
from edithunt.models import db
import os

app = create_app()

@app.template_filter('format_number')
def format_number(value):
    try:
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return value

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 10000))  # Render가 지정한 포트 사용, 없으면 10000
    app.run(host='0.0.0.0', port=port, debug=True) 