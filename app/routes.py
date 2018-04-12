from app import app, db  
from flask import render_template, url_for, redirect, flash, request
from app.forms import LoginForm, RegistationForm, AddUserForm, ManageUser, UpdateUserForm, DeleteUserForm, SelectUserForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Roles, UserRole
from werkzeug.urls import url_parse


@app.route('/profile')
@login_required
def profile():
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', role=role)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/contact")
def about():
    return render_template("contact.html")


@app.route("/attorneys")
def contact():
    return render_template("attorneys.html")


@app.route("/news")
def news():
    return render_template("news.html")


@app.route("/where")
def where():
    return render_template("where.html")


@app.route("/who")
def who():
    return render_template("who.html")


@app.route('/login',  methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Incorrect email or password. Please try again!')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('profile')
        return redirect(next_page)
    return render_template('login.html', title="Log In", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistationForm()
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        role = UserRole()
        role.user_id = user.id
        db.session.add(role)
        db.session.commit()
        flash('Your account has been successfully created!')
        return redirect(url_for('profile'))
    return render_template('login.html', title="Register", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/adminupdate')
def adminupdate():
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    return render_template('adminupdate.html', roles=roles)

@app.route('/admin_manage_user', methods=['GET', 'POST'])
@login_required
def admin_manage_user():
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    if role.roles.id != 3:
        redirect(url_for('index'))
        flash('You do not have access to that page. Please contact your administrator.')
    form = ManageUser()
    if form.validate_on_submit() and form.action.data == 'add':
      return redirect(url_for('add_user'))
    if form.validate_on_submit() and form.action.data == 'update':
        return redirect(url_for('update_user'))
    if form.validate_on_submit() and form.action.data == 'delete':
        return redirect(url_for('delete_user'))
    return render_template('admin.html', title="Admin Add User", form=form, roles=roles)
    
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    if role.roles.id != 3:
        redirect(url_for('index'))
        flash('You do not have access to that page. Please contact your administrator.')
    form = AddUserForm()
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data)
        user.set_password(form.first_name.data)
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        role = UserRole(role_id=form.role.data)
        role.user_id = user.id
        db.session.add(role)
        db.session.commit()
        flash('You have successfully created {} {}\'s account!'.format(user.first_name, user.last_name))
        return redirect(url_for('admin_manage_user'))
    return render_template('admin_update_user.html', title="Add User", form=form, roles=roles)


@app.route('/update_user/<id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    user = UserRole.query.filter_by(user_id=id).first()
    if role.roles.id != 3:
        redirect(url_for('index'))
        flash('You do not have access to that page. Please contact your administrator.')
    form = UpdateUserForm()
    if form.validate_on_submit():
        user = UserRole.query.filter_by(user_id=id).first()
        user.user.first_name = form.first_name.data
        user.user.last_name = form.last_name.data
        user.user.email = form.email.data
        user.role_id = form.role.data
        db.session.add(user)
        db.session.add(user.user)
        db.session.commit()
        flash('You have successfully updated {} {}\'s account!'.format(user.user.first_name, user.user.last_name))
        return redirect(url_for('admin_manage_user'))
    return render_template('admin_update_user.html', title="Update {} {}\'s Account".format(user.user.first_name, user.user.last_name), form=form, roles=roles)

@app.route('/delete_user/<id>', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    user = UserRole.query.filter_by(user_id=id).first()
    name = user.user.first_name + " " + user.user.last_name
    if role.roles.id != 3:
        redirect(url_for('index'))
        flash('You do not have access to that page. Please contact your administrator.')
    form = DeleteUserForm()
    if form.validate_on_submit():
        UserRole.query.filter_by(user_id=id).delete()
        User.query.filter_by(id=id).delete()
        db.session.commit()
        flash('You have successfully deleted {}\'s account!'.format(name))
        return redirect(url_for('admin_manage_user'))
    return render_template('admin_update_user.html', title="Confirm Delete: {}".format(name), form=form, roles=roles)


@app.route('/portal', methods=['GET', 'POST'])
@login_required
def portal():
    roles = UserRole.query.all()
    role = UserRole.query.filter_by(user_id=current_user.id).first()
    if role.roles.id != 2:
        redirect(url_for('index'))
        flash('You do not have access to that page. Please contact your administrator.')
    return render_template('portal.html', roles=roles)
