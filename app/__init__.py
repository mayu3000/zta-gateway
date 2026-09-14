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
                         email="admin@local",
                         password_hash=generate_password_hash("admin123"),
                         status="approved",
                         is_admin=True,
                         email_verified=True)
            db.session.add(admin)
            db.session.commit()

    from .routes import main
    app.register_blueprint(main)

    # Phase 7 captive portal: gate unapproved devices at the login page.
    from .middleware import captive_portal_check
    app.before_request(captive_portal_check)

    return app
