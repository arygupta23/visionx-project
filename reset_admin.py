from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Find the user by ID or Name
    user = User.query.filter_by(name="Admin").first()
    
    if user:
        print(f"Found user: {user.name} ({user.email})")
        new_password = "admin123"
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        print(f"Password for '{user.name}' has been reset to: {new_password}")
    else:
        print("User 'Admin' not found.")
