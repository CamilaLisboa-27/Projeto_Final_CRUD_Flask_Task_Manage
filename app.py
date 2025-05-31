import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Buscar infos do .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

DATABASE = './instance/tasks.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# -----------------------
# User class para Flask-Login
class User(UserMixin):
    def __init__(self, id_, username, password_hash):
        self.id = id_
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        con = get_db()
        cur = con.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cur.fetchone()
        if not user:
            return None
        return User(user['id'], user['username'], user['password'])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# -----------------------
# Database
def get_db():
    con = getattr(g, '_database', None)
    if con is None:
        con = g._database = sqlite3.connect(DATABASE)
        con.row_factory = sqlite3.Row
    return con

@app.teardown_appcontext
def close_connection(exception):
    con = getattr(g, '_database', None)
    if con is not None:
        con.close()

# -----------------------
# Rotas de autenticação
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        con = get_db()

        # Verifica se usuário existe
        user = con.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            flash('Usuário já existe!')
            return redirect(url_for('register'))

        # Cria hash da senha
        password_hash = generate_password_hash(password)
        con.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
        con.commit()
        flash('Registrado com sucesso! Faça login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        con = get_db()
        user = con.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'], user['password'])
            login_user(user_obj)
            flash('Login efetuado com sucesso!')
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha incorretos!')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.')
    return redirect(url_for('login'))

# -----------------------
# Rotas de gerenciador de tarefas

@app.route('/')
@login_required
def index():
    con = get_db()
    tasks = con.execute('SELECT * FROM tasks WHERE user_id = ?', (current_user.id,)).fetchall()
    return render_template('index.html', tasks=tasks)

@app.route('/task/create', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        con = get_db()
        con.execute('INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)', (title, description, current_user.id))
        con.commit()
        flash('Tarefa criada!')
        return redirect(url_for('index'))
    return render_template('create_task.html')

@app.route('/task/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    con = get_db()
    task = con.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user.id)).fetchone()
    if not task:
        flash('Tarefa não encontrada!')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        con.execute('UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?', (title, description, task_id, current_user.id))
        con.commit()
        flash('Tarefa atualizada!')
        return redirect(url_for('index'))

    return render_template('edit_task.html', task=task)

@app.route('/task/delete/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    con = get_db()
    con.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user.id))
    con.commit()
    flash('Tarefa deletada!')
    return redirect(url_for('index'))

# -----------------------
# Inicialização do banco de dados
def init_db():
    con = sqlite3.connect(DATABASE)
    with open('schema.sql') as f:
        con.executescript(f.read())
    con.commit()
    con.close()

if __name__ == '__main__':
    #init_db()
    app.run(debug=True)
