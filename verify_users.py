from app import app, db, User

with app.app_context():
    users = User.query.all()
    print(f"{'ID':<5} {'Name':<20} {'Email':<30} {'Role':<15} {'Status'}")
    print("-" * 80)
    for user in users:
        print(f"{user.id:<5} {user.name:<20} {user.email:<30} {user.role:<15} {user.status}")
