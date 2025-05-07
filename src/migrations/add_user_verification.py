from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edithunt.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

def upgrade():
    with app.app_context():
        # Add new columns to user table
        db.engine.execute('ALTER TABLE user ADD COLUMN is_verified BOOLEAN DEFAULT FALSE')
        db.engine.execute('ALTER TABLE user ADD COLUMN verify_token VARCHAR(100)')
        db.engine.execute('ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)')
        db.engine.execute('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')

def downgrade():
    with app.app_context():
        # Remove columns from user table
        db.engine.execute('ALTER TABLE user DROP COLUMN is_verified')
        db.engine.execute('ALTER TABLE user DROP COLUMN verify_token')
        db.engine.execute('ALTER TABLE user DROP COLUMN reset_token')
        db.engine.execute('ALTER TABLE user DROP COLUMN is_admin')

if __name__ == '__main__':
    upgrade() 