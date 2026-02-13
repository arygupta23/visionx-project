from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    print("Connecting to database...")
    user = User.query.filter_by(name="Admin User").first()
    
    if user:
        print(f"Found user: {user.name}")
        print(f"Current hash: {user.password_hash}")
        
        # Force reset
        new_hash = generate_password_hash("admin123")
        user.password_hash = new_hash
        db.session.commit()
        
        print("Password reset successfully to 'admin123'")
        print(f"New hash: {user.password_hash}")
    else:
        print("User 'Admin User' not found! Seeding it now...")
        default_pw = generate_password_hash("admin123")
        new_user = User(
            name="Admin User", 
            role="Administrator", 
            status="Active", 
            initials="AC", 
            color="bg-primary", 
            password_hash=default_pw
        )
        db.session.add(new_user)
        db.session.commit()
        print("Created 'Admin User' with password 'admin123'")
