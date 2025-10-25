from main import app, db, User

def create_admin_and_db():
    with app.app_context():
        db.create_all()
        admin_email = "mouhamadn63@gmail.com"
        if not User.query.filter_by(email=admin_email).first():
            admin_user = User(email=admin_email, is_admin=True)
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created.")

if __name__ == '__main__':
    create_admin_and_db()
