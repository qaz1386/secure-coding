import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or user['is_admin'] != 1:
            flash('관리자만 접근할 수 있습니다.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@socketio.on('join_room')
def handle_join(data):
    room = data['room']
    join_room(room)

@socketio.on('private_message')
def handle_private_message(data):
    room = data['room']
    message = data['message']
    from_id = data['from_id']
    to_id = data['to_id']

    # DB에 저장
    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())
    cursor.execute("INSERT INTO message (id, from_id, to_id, content) VALUES (?, ?, ?, ?)",
                   (msg_id, from_id, to_id, message))
    db.commit()

    emit('receive_message', {'message': message, 'from_id': from_id}, to=room)

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                balance INTEGER DEFAULT 0,
                bank_account TEXT DEFAULT ''
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT '판매중'
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

# 관리자 페이지: 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, is_active, is_admin FROM user")
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users)

# 사용자 삭제
@app.route('/admin/user/<user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_active FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        new_state = 0 if user['is_active'] == 1 else 1
        cursor.execute("UPDATE user SET is_active = ? WHERE id = ?", (new_state, user_id))
        db.commit()
        flash('사용자 상태가 변경되었습니다.')
    return redirect(url_for('admin_users'))

# 관리자/작성자 - 상품 목록 확인 및 관리
@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    is_admin = cursor.fetchone()['is_admin']

    if is_admin:
        cursor.execute("SELECT product.*, user.username FROM product JOIN user ON product.seller_id = user.id")
    else:
        cursor.execute("SELECT product.*, user.username FROM product JOIN user ON product.seller_id = user.id WHERE seller_id = ?", (session['user_id'],))

    products = cursor.fetchall()
    return render_template('admin_products.html', products=products, is_admin=is_admin)

# 상품 삭제 기능 (관리자 또는 작성자)
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('admin_products'))

    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if user['is_admin'] != 1 and product['seller_id'] != session['user_id']:
        flash('권한이 없습니다.')
        return redirect(url_for('admin_products'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"\W", password):
            flash('비밀번호는 8자 이상, 숫자 및 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)
        is_admin = 1 if username == 'master' else 0
        cursor.execute("INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
               (user_id, username, hashed_pw, is_admin))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# user_list: 모든 사용자 리스트 표시
@app.route('/users')
def user_list():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()
    my_id = session['user_id']
    if query:
        cursor.execute("""
            SELECT id, username, bio FROM user 
            WHERE username LIKE ? AND id != ?
        """, (f'%{query}%', my_id))
    else:
        cursor.execute("SELECT id, username, bio FROM user WHERE id != ?", (my_id,))
    users = cursor.fetchall()
    return render_template('user_list.html', users=users, query=query)

#1대1 채팅: 사용자 ID로 방 생성
@app.route('/chat/<username>')
def private_chat(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 대상 유저 확인
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    target = cursor.fetchone()

    if not target or target['id'] == session['user_id']:
        flash("잘못된 대상입니다.")
        return redirect(url_for('dashboard'))

    # 기존 메시지 로딩
    cursor.execute("""
        SELECT * FROM message 
        WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], target['id'], target['id'], session['user_id']))
    messages = cursor.fetchall()

    return render_template('private_chat.html', messages=messages, target=target)

# 비밀번호 변경
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        if len(new) < 8 or not re.search(r"\d", new) or not re.search(r"\W", new):
            flash('비밀번호는 8자 이상, 숫자 및 특수문자를 포함해야 합니다.')
            return redirect(url_for('change_password'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], current):
            new_hash = generate_password_hash(new)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_hash, session['user_id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
            return redirect(url_for('profile'))
        else:
            flash('현재 비밀번호가 일치하지 않습니다.')
    return render_template('change_password.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        bank_account = request.form.get('bank_account', '')
        cursor.execute("UPDATE user SET bio = ?, bank_account = ? WHERE id = ?", (bio, bank_account, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 수정 기능 (작성자 또는 관리자)
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if user['is_admin'] != 1 and product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        cursor.execute("""
            UPDATE product SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('edit_product.html', product=product)

@app.route('/product/<product_id>/confirm', methods=['POST'])
def confirm_payment(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 이미 거래 완료 상태면 차단
    if product['status'] == '거래완료':
        flash("이 상품은 이미 거래가 완료되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 상태 변경
    cursor.execute("UPDATE product SET status = '거래완료' WHERE id = ?", (product_id,))
    db.commit()

    flash('입금 완료가 확인되었습니다. 거래가 완료 처리되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/product/<product_id>/start', methods=['POST'])
def start_transaction(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 판매자가 본인 상품에 거래 시작 못하게 제한
    cursor.execute("SELECT seller_id, status FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] == session['user_id']:
        flash('자신의 상품에 거래를 시작할 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['status'] != '판매중':
        flash('이미 거래가 시작된 상품입니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE product SET status = '거래중' WHERE id = ?", (product_id,))
    db.commit()
    flash('거래를 시작했습니다. 입금 후 판매자에게 알려주세요.')
    return redirect(url_for('view_product', product_id=product_id))


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    current_user = None
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, user=current_user)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app,host='0.0.0.0', debug=True)
