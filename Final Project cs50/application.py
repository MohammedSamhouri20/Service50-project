from flask import Flask, render_template, url_for, session, request, redirect, flash
from cs50 import SQL
import os
from datetime import date
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
db = SQL("sqlite:///data.db")


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def home():
    services = db.execute("SELECT * FROM services")
    return render_template("home.html", service=services)

@app.route('/home/<num>')
def homepages(num):
    service = db.execute("SELECT * FROM services WHERE service_id = ?", num)
    if len(service) != 1:
        return render_template('apology.html', apology="No AD!")
    return render_template("pages.html", page=service)


@app.route('/favorites')
@login_required
def favorites():
    favorite = db.execute("SELECT * FROM services WHERE service_id IN (SELECT service_id FROM favorite WHERE user_id = ?)", session['user_id'])
    return render_template('favorites.html', favorite=favorite)


@app.route('/favorites/<num>/<num1>')
@login_required
def favpages(num, num1):
    service = db.execute("SELECT * FROM services WHERE service_id = ?", num)
    favorite = db.execute("SELECT * FROM favorite WHERE service_id = ? AND user_id = ?", num, session['user_id'])

    if len(service) == 1 and len(favorite) != 1:
        return render_template('apology.html', apology="You Did Not Add it!")
    elif len(service) != 1:
        return render_template('apology.html', apology="No AD!")
    return render_template("pages.html", num1=num1, page=service)


@app.route('/favorite/<ty>/<num>')
@login_required
def manage_favorite(ty, num):
    favorite = db.execute("SELECT * FROM favorite WHERE service_id = ? AND user_id = ?", num, session['user_id'])
    service = db.execute("SELECT * FROM services WHERE service_id = ?", num)
    if len(service) != 1:
        return render_template('apology.html', apology="No AD!")

    if ty == 'add':
        if len(favorite) != 1:
            db.execute("INSERT INTO favorite (user_id, service_id) VALUES (?, ?)", session['user_id'], num)
            return redirect('/favorites')
        else:
            return render_template('apology.html', apology="You've Already Added it!")
    elif ty == 'remove':
        if len(favorite) != 1:
            return render_template('apology.html', apology="You Did Not Even Add it!")
        else:
            db.execute("DELETE FROM favorite WHERE user_id = ? AND service_id = ?", session['user_id'], num)
            return redirect('/favorites')

@app.route('/ads')
@login_required
def services():
    service = db.execute("SELECT * FROM services WHERE user_id = ?", session['user_id'])
    return render_template("services.html", service=service)


@app.route('/ads/<int:num>/<int:num1>')
@login_required
def adpages(num, num1):
    service = db.execute("SELECT * FROM services WHERE service_id = ?", num)
    if len(service) != 1:
        return render_template('apology.html', apology="No AD!")
    return render_template("pages.html", num1=num1, page=service)

@app.route('/ads/<string:ty>/<int:num>')
@login_required
def manage_ads(ty, num):
    service = db.execute("SELECT * FROM services WHERE service_id = ? AND user_id = ?", num, session['user_id'])
    if len(service) != 1:
        return render_template('apology.html', apology="No AD!")

    if ty == 'edit':
            return render_template('edit.html', service=service)
    elif ty == 'remove':
        db.execute("DELETE FROM services WHERE user_id = ? AND service_id = ?", session['user_id'], num)
        db.execute("DELETE FROM favorite WHERE service_id = ?", num)
        return redirect('/ads')

@app.route('/edit/<int:num>', methods=['POST'])
@login_required
def edit(num):
    service = db.execute("SELECT * FROM services WHERE service_id = ? AND user_id = ?", num, session['user_id'])
    if len(service) != 1:
        return render_template('apology.html', apology="No AD!")
    else:
        db.execute("UPDATE services SET name = ?, desc = ?, price = ?, category = ?, contact = ?, date = ? WHERE user_id = ? AND service_id = ?", request.form.get('title'), request.form.get('description'), request.form.get('price'), request.form.get('category'), request.form.get('contact'), date.today(), session['user_id'], num)
        return redirect('/ads')


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_ad():
    if request.method == "GET":
        return render_template('add_ad.html')
    else:
        db.execute("INSERT INTO services (user_id, name, desc, price, category, contact, date) VALUES (?, ?, ?, ?, ?, ?, ?)", session['user_id'], request.form.get('title'), request.form.get('description'), request.form.get('price'), request.form.get('category'), request.form.get('contact'), date.today())
        return redirect('/ads')

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == "GET":
        return render_template("login.html")
    else:
        user = db.execute("SELECT * FROM users")
        for u in user:
            if request.form.get('username') == u['username'] and check_password_hash(u['hash'] ,request.form.get('pass')):
                session['user_id'] = u['user_id']
                return redirect('/')
        return render_template('apology.html', apology="Something Wrong In Username/Password!")



@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()

    if request.method == 'GET':
        return render_template("register.html")
    else:
        user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get('username'))

        if request.form.get('username'):
            for l in request.form.get('username'):
                if len(request.form.get('username')) < 8:
                    return render_template('apology.html', apology='The Username Must Be 8 Letters Or Numbers At Least')
                if not (l >= 'a' and l <= 'z' or l >= 'A' and l <= 'Z' or l >= '0' and l <= '9' or l == '_'):
                    return render_template('apology.html', apology='Letters, Numbers And _ Only!')
        else:
            return render_template('apology.html', apology='No Username!')

        if len(user) == 1:
            return render_template('apology.html', apology='The Username Is Taken, Please Choose Another One!')

        if not request.form.get('pass'):
            return render_template('apology.html', apology='No Password!')
        else:
            if len(request.form.get('pass')) < 6:
                    return render_template('apology.html', apology='The Password Must Be 6 Letters Or Numbers At Least')
            for l in request.form.get('pass'):
                if not (l >= 'a' and l <= 'z' or l >= 'A' and l <= 'Z' or l >= '0' and l <= '9'):
                    return render_template('apology.html', apology='Letters And Numbers Only')
            if request.form.get('pass') != request.form.get('repass'):
                return render_template('apology.html', apology='Confirmation Error!')

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get('username'), generate_password_hash(request.form.get('pass')))
        username = request.form.get('username')
        return render_template('login.html', username=username)

@app.route('/account')
@login_required
def account():
    return render_template("account.html")

@app.route('/settings/<string:var>', methods=['GET', 'POST'])
@login_required
def setting(var):
    user = db.execute('SELECT * FROM users WHERE user_id = ?', session['user_id'])
    if request.method == 'GET':
        return render_template("setting.html", var=var)
    else:
        if len(user) == 1:
            if var == 'password':
                if not check_password_hash(user[0]['hash'] ,request.form.get('opass')):
                    return render_template('apology.html', apology="Old Password Is Not Correct!")

                if not request.form.get('newpass'):
                    return render_template('apology.html', apology='Write New Password!')
                else:
                    if len(request.form.get('newpass')) < 6:
                        return render_template('apology.html', apology='The Password Must Be 6 Letters Or Numbers At Least')
                    for l in request.form.get('newpass'):
                        if not (l >= 'a' and l <= 'z' or l >= 'A' and l <= 'Z' or l >= '0' and l <= '9'):
                            return render_template('apology.html', apology='Letters And Numbers Only')

                    if request.form.get('newpass') != request.form.get('renewpass'):
                        return render_template('apology.html', apology='Confirmation Error!')

                    db.execute('UPDATE users SET hash = ? WHERE user_id = ?', generate_password_hash(request.form.get('newpass')), session['user_id'])

            elif var == 'username':
                if request.form.get('ouser') != user[0]['username']:
                    return render_template('apology.html', apology="Username Is Not Correct!")
                else:
                    if request.form.get('newuser'):
                        for l in request.form.get('newuser'):
                            if len(request.form.get('newuser')) < 8:
                                return render_template('apology.html', apology='The Username Must Be 8 Letters Or Numbers At Least')
                            if not (l >= 'a' and l <= 'z' or l >= 'A' and l <= 'Z' or l >= '0' and l <= '9' or l == '_'):
                                return render_template('apology.html', apology='Letters, Numbers And _ Only!')

                        u = db.execute("SELECT * FROM users WHERE username = ?", request.form.get('newuser'))
                        if len(u) == 1:
                            return render_template('apology.html', apology='The Username Is Taken, Please Choose Another One!')
                    else:
                        return render_template('apology.html', apology='No New Username!')

                    if not check_password_hash(user[0]['hash'] ,request.form.get('pass')):
                        return render_template('apology.html', apology="Password Is Not Correct!")

                    db.execute('UPDATE users SET username = ? WHERE user_id = ?', request.form.get('newuser'), session['user_id'])

            elif var == 'delete':
                if request.form.get('yes'):
                    db.execute("DELETE FROM users WHERE user_id = ?", session['user_id'])
                    db.execute("DELETE FROM services WHERE user_id = ?", session['user_id'])
                    db.execute("DELETE FROM favorite WHERE user_id = ?", session['user_id'])
                    session.clear()
            return redirect('/')
        else:
            return render_template('apology.html', apology="Something Wrong!")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)