from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from filters import split_into_lines
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'stepan_olegovich'

app.jinja_env.filters['split_into_lines'] = split_into_lines


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def create_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_banned INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0, bio TEXT, age INTEGER, city TEXT, photo TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
    cursor.execute('CREATE TABLE IF NOT EXISTS friends (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, friend_id INTEGER, UNIQUE(user_id, friend_id), FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(friend_id) REFERENCES users(id))')
    conn.commit()
    conn.close()



def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Главная страница
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('main'))
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        conn.close()
        return 'Пользователь с таким логином уже существует. Пожалуйста, выберите другой логин.'

    is_admin = 1 if username == 'admin' else 0
    
    cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', (username, password, is_admin))
    conn.commit()
    conn.close()
    
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            session['username'] = username
            session['user_id'] = user['id']  # Добавляем user_id в сессию
            session['is_admin'] = user['is_admin']
            
            if username == 'admin':
                session['is_admin'] = 1
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_admin = 1 WHERE username = ?', (username,))
                conn.commit()
                conn.close()
                
            print(f'Logged in as {username} with admin rights: {session["is_admin"]}')
            return redirect(url_for('main'))
        else:
            return 'Неверный логин или пароль. Попробуйте еще раз.'
    
    return render_template('index.html')


@app.route('/main')
def main():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    conn.close()

    if user['is_banned'] == 1:
        return render_template('banned.html')

    return render_template('main.html', user=user)


# Редактирование профиля

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = 'static/uploads'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_bio = request.form['bio']
        new_age = request.form['age']
        new_city = request.form['city']
        username = session['username']

        conn = get_db_connection()
        cursor = conn.cursor()

        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                photo_path = os.path.join('uploads', filename).replace('\\', '/')  # <-- изменение
                cursor.execute('UPDATE users SET photo = ? WHERE username = ?', (photo_path, username))

       
        cursor.execute('UPDATE users SET bio = ?, age = ?, city = ? WHERE username = ?', (new_bio, new_age, new_city, username))
        conn.commit()
        conn.close()

        return redirect(url_for('profile'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT bio, age, city FROM users WHERE username = ?', (session['username'],))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    conn.close()
    if user['is_banned'] == 1:
        return render_template('banned.html')

    return render_template('edit_profile.html', bio=user['bio'], age=user['age'], city=user['city'])


@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    conn.close()
    if user['is_banned'] == 1:
        return render_template('banned.html')
    return render_template('profile.html', user=user)

@app.route('/profile/<username>')
def view_profile(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user['is_banned'] == 1:
        return render_template('banned.html')
    
    # Допустим, что текущий пользователь хранится в сессии
    current_user_id = session.get('user_id')
    
    return render_template('view_profile.html', user=user, current_user_id=current_user_id)
# Чат
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT is_banned FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    conn.close()

    if user and user['is_banned']:
        return render_template('banned.html')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM messages ORDER BY timestamp DESC')
    messages = cursor.fetchall()
    
    if request.method == 'POST':
        username = session['username']
        message = request.form['message'][:100] 
        
        cursor.execute('INSERT INTO messages (username, message) VALUES (?, ?)', (username, message))
        conn.commit()
        conn.close()
        
        return redirect(url_for('chat')) 

    conn.close()
    return render_template('chat.html', messages=messages)




@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    message = request.form['message']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (username, message) VALUES (?, ?)', (username, message))
    conn.commit()
    conn.close()

    return redirect(url_for('chat'))

@app.route('/users')
def users():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
  
    cursor.execute('SELECT is_banned FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    
    if user and user['is_banned']:
        conn.close()
        return render_template('banned.html')
    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    
    return render_template('users_list.html', users=users)

def create_private_messages_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS private_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_username TEXT,
                        receiver_username TEXT,
                        message TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')
    conn.commit()
    conn.close()



@app.route('/chat/<username>', methods=['GET', 'POST'])
def private_chat(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = session['username']

    if request.method == 'POST':
        message = request.form['message']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO private_messages (sender_username, receiver_username, message) VALUES (?, ?, ?)',
                       (current_user, username, message))
        conn.commit()
        conn.close()

        return redirect(url_for('private_chat', username=username))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM private_messages 
                      WHERE (sender_username = ? AND receiver_username = ?) 
                         OR (sender_username = ? AND receiver_username = ?)
                      ORDER BY timestamp ASC''', (current_user, username, username, current_user))
    messages = cursor.fetchall()
    conn.close()
    return render_template('private_chat.html', messages=messages, receiver=username)





@app.route('/admin/users', methods=['GET'])
def admin_users():
    if 'username' not in session:
        flash('Вы не авторизованы!', 'error')
        return redirect(url_for('logout'))

    if not session.get('is_admin'):
        flash('У вас нет прав администратора!', 'error')
        return redirect(url_for('logout'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_users.html', users=users)


@app.route('/admin/ban/<username>', methods=['POST'])
def admin_ban_user(username):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_banned = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash(f'User {username} has been banned.', 'success')
    return redirect(url_for('admin_users'))



@app.route('/admin/users/edit/<username>', methods=['GET', 'POST'])
def edit_user(username):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_bio = request.form['bio']
        new_age = request.form['age']
        new_city = request.form['city']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET bio = ?, age = ?, city = ? WHERE username = ?', (new_bio, new_age, new_city, username))
        conn.commit()
        conn.close()

        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<username>', methods=['POST'])
def delete_user(username):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/unban/<username>', methods=['POST'])
def admin_unban_user(username):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_banned = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash(f'User {username} has been unbanned.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/make_admin/<username>', methods=['POST'])
def admin_make_admin(username):
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_admin = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash(f'User {username} is now an admin.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/remove_admin/<username>', methods=['POST'])
def admin_remove_admin(username):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_admin = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash(f'User {username} is no longer an admin.', 'success')
    return redirect(url_for('admin_users'))



def get_friends(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''SELECT users.id, users.username 
                      FROM friends 
                      JOIN users ON friends.friend_id = users.id 
                      WHERE friends.user_id = ?''', (user_id,))
    friends = cursor.fetchall()
    conn.close()
    return friends


def add_friend(user_id, friend_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO friends (user_id, friend_id) VALUES (?, ?)', (user_id, friend_id))
    cursor.execute('INSERT INTO friends (user_id, friend_id) VALUES (?, ?)', (friend_id, user_id))  # Установка двунаправленной дружбы
    conn.commit()
    conn.close()



# Профиль пользователя с возможностью управления друзьями
@app.route('/my_profile')
def my_profile():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']  # Получаем user_id из сессии
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    friends = get_friends(user_id)
    
    conn.close()
    
    return render_template('list_friend.html', user=user, friends=friends)

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend_route(friend_id):
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    friend_id = request.form.get('friend_id')
    
    add_friend(user_id, friend_id)
    
    flash('Пользователь добавлен в друзья!', 'success')
    return redirect(url_for('view_profile', username=session['username']))



@app.route('/send_friend_request/<int:friend_id>', methods=['POST'])
def send_friend_request(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if user_id == friend_id:
        flash('Вы не можете добавить себя в друзья', 'error')
        return redirect(url_for('view_profile', username=session['username']))
    
    if are_friends(user_id, friend_id):
        flash('Пользователь уже у вас в друзьях', 'error')
        return redirect(url_for('view_profile', username=session['username']))
    
    if friend_request_sent(user_id, friend_id):
        flash('Запрос уже отправлен', 'error')
        return redirect(url_for('view_profile', username=session['username']))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (?, ?)', (user_id, friend_id))
    conn.commit()
    conn.close()
    
    flash('Запрос на добавление в друзья отправлен', 'success')
    return redirect(url_for('view_profile', username=session['username']))

@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
def remove_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if not are_friends(user_id, friend_id):
        flash('Этот пользователь не у вас в друзьях', 'error')
        return redirect(url_for('view_profile', username=session['username']))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
                   (user_id, friend_id, friend_id, user_id))
    conn.commit()
    conn.close()
    
    flash('Пользователь удален из друзей', 'success')
    return redirect(url_for('view_profile', username=session['username']))

def are_friends(user_id, friend_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
                   (user_id, friend_id, friend_id, user_id))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def friend_request_sent(from_user_id, to_user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM friend_requests WHERE from_user_id = ? AND to_user_id = ?', (from_user_id, to_user_id))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Регистрация функций в контексте шаблонов

@app.context_processor
def utility_processor():
    return dict(
        are_friends=are_friends,
        friend_request_sent=friend_request_sent
    )




# Выход из аккаунта
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))



if __name__ == '__main__':
    create_table()
    create_private_messages_table()
    app.run(debug=True)