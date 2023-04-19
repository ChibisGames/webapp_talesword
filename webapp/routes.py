from flask import request, redirect, render_template, url_for, flash, session
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from webapp import app, db
from webapp.models import Feedback, User


@app.route('/update', methods=['GET'])
@app.route('/', methods=['GET'])
def updates_page():
    with open('webapp/static/text/updates.txt', 'r', encoding="utf-8") as f:
        updates_data = f.readlines()[0]
    return render_template('index.html', updates=updates_data)


@app.route('/feedbacks', methods=['GET'])
def feedbacks_page():
    return render_template('feedbacks.html',
                           items=User.query.filter(Feedback.id > 0).all())


@app.route('/feedback_form', methods=['GET', 'POST'])
@login_required
def feedback_form_page():
    edit = False
    if 'user' in session:
        user = User.query.filter(User.login == session['user']).first()
    else:
        return redirect(url_for('logout_page'))
    try:
        if user.feedbacks:
            edit = True
    except Exception:
        pass

    if request.method == 'POST':
        text = request.form['text']
        if edit:
            user.feedbacks[0].text = text
        else:
            feedback = Feedback(text=text, user=user)
            user.feedbacks.append(feedback)
        db.session.commit()
        return redirect(url_for('feedbacks_page'))
    else:
        return render_template('feedback_form.html', edit=edit)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)

            #  next_page = request.args.get('next')
            session['user'] = login

            redirect(url_for('feedback_form_page'))
        else:
            flash("login or password not correct")
    else:
        flash("please fill login and password")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Заполни меня')
        elif password != password2:
            flash('Пароли не равны')
        else:
            hash_psw = generate_password_hash(password)
            new_user = User(login=login)
            new_user.password = hash_psw
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            session['user'] = new_user.login
            return redirect(url_for('feedback_form_page'))

        return redirect(url_for('login_page'))
    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('feedbacks_page'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page'))
    return response
