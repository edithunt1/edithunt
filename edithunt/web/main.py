from flask import Blueprint, render_template, request
from ..models import Portfolio, User

main = Blueprint('main', __name__)

@main.route('/')
def index():
    featured_portfolios = Portfolio.query.order_by(Portfolio.views.desc()).limit(6).all()
    recent_portfolios = Portfolio.query.order_by(Portfolio.created_at.desc()).limit(6).all()
    top_creators = User.query.join(Portfolio).group_by(User.id).order_by(db.func.count(Portfolio.id).desc()).limit(4).all()
    
    return render_template('main/index.html',
                         featured_portfolios=featured_portfolios,
                         recent_portfolios=recent_portfolios,
                         top_creators=top_creators)

@main.route('/search')
def search():
    query = request.args.get('q', '')
    portfolios = Portfolio.query.filter(
        (Portfolio.title.ilike(f'%{query}%')) |
        (Portfolio.description.ilike(f'%{query}%'))
    ).all()
    
    return render_template('main/search.html', portfolios=portfolios, query=query) 