# Flask Auth App

A secure and extensible **Flask-based authentication system** designed to simplify user management and enhance security.

---

## ✨ Key Features

- 🔒 **User Authentication**: Register, Login, Logout
- 📧 **Email Verification**: Secure account activation
- 🔁 **Password Reset**: Token-based email reset
- 🧠 **Role-Based Dashboards**: User/Admin separation
- 🚫 **Account Lockout**: Protection after failed attempts
- 🔐 **Token Expiration Control**: Enhanced security
- 📬 **SMTP Support**: Gmail/Outlook integration
- 🌐 **Environment Configuration**: `.env` file support
- 📦 **SQLAlchemy ORM**: Database management

---

## 🛠️ Technologies Used

- **Python 3.11+**
- **Flask**: Web framework
- **Flask-Mail**: Email handling
- **Flask-SQLAlchemy**: ORM for database
- **Flask-Migrate**: Database migrations
- **Flask-WTF**: Form handling
- **Python-dotenv**: Environment variable management
- **SQLite / PostgreSQL / MySQL**: Configurable databases

---

## 🗂️ Folder Structure

```plaintext
Flask_auth_app/
│
├── app/
│   ├── __init__.py       # Flask app factory
│   ├── config.py         # Configuration settings
│   ├── models/           # SQLAlchemy models
│   ├── routes/           # Blueprint routes
│   ├── services/         # Business logic (e.g., email, tokens)
│   ├── utils/            # Helper functions and classes
│   ├── templates/        # Jinja2 HTML templates
│   ├── static/           # CSS, JS, images
│
├── instance/             # Instance-specific settings or DBs
├── logs/                 # Application logs
├── migrations/           # Alembic DB migrations
├── venv/                 # Virtual environment (ignored)
├── .env                  # Environment variables (ignored)
├── .gitignore
├── app.py                # Entry point for running the app
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/PreciousEzeigbo/Flask_auth_app.git
cd Flask_auth_app
```

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root with the following:

```plaintext
SECRET_KEY=your_super_secret_key
DATABASE_URL=sqlite:///instance/users.db

MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_DEFAULT_SENDER=your_email@example.com
```

### 5. Run Database Migrations

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### 6. Start the Application

```bash
flask run
```

---

## ✅ Security Best Practices

- Never commit your `.env` file to version control.
- Use strong passwords and app-specific passwords for email services.
- For production, enable HTTPS, rate limiting, and secure cookie settings.

---

## 🚀 Future Enhancements

- OAuth Login (Google, GitHub)
- Admin Dashboard Interface
- User Profile Editing
- Two-Factor Authentication (2FA)
- API Endpoints with JWT Authentication

---

## 🙌 Credits

Developed with ❤️ by [Precious Ezeigbo](https://github.com/PreciousEzeigbo)
