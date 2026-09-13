from flask import Flask
from .models import db, User
from werkzeug.security import generate_password_hash

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-later"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///../db/zta.db"

    db.init_app(app)

    with app.app_context():
        db.create_all()
        # create a default admin user if none exists (Phase 1 shortcut)
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin",
                         password_hash=generate_password_hash("admin123"))
            db.session.add(admin)
            db.session.commit()

    from .routes import main
    app.register_blueprint(main)

    return app
