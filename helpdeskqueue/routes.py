import os
import secrets
#from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from helpdeskqueue import app, db, bcrypt
from helpdeskqueue.forms import LoginForm, RegistrationForm, QueueForm, PageAction
from helpdeskqueue.models import User, Post
from flask_login import login_user, logout_user, current_user, login_required

status = ['open', 'assisting', 'complete', 'canceled']

# Home and Register
#####################################################################################
#####################################################################################

@app.route("/")
@app.route("/home", methods = ['GET', 'POST'])
def home():
    if current_user.is_authenticated and (current_user.user_type == 'user'):
        return redirect(url_for('user_page'))
    if current_user.is_authenticated and (current_user.user_type == 'admin'):
        return redirect(url_for('admin'))
    count = "5"
    return render_template('home.html', count = count)

@app.route("/register", methods = ['GET', 'POST'])
def register():
    ## logic for if user is authenticated take them straight home
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    ## create variable form and make it call RegistrationForm() from the forms.py which holds requirements for the registration form
    form = RegistrationForm()
    ## logic to validate user account upon submit
    if form.validate_on_submit():
        ## create hashed_password variable,hashes password pulling from the html form and decoding it as utf-8
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        ## create user variable, grab User class with needed attributes to input to db, always pull hashed_password not form.password.data, otherwise you wont get the encrypted password
        user = User(username = form.username.data, user_type='user', email = form.email.data, password = hashed_password)
        ## creates db session and adds user
        db.session.add(user)
        ## commits user creation to db
        db.session.commit()
        login_user(user)
        ## flash function will run once redirected to the home.html which is being redirected useing the redirect function and using the url_for('home) pointing at the function home() which isnt the same as the route ("/home
        flash(f'Your account has been created!! You are now able to log in', 'success')
        return redirect(url_for('create_post'))
        ## form=form is pushing the RegistrationForm() from the forms.py giving all the attributes from that class
    return render_template('register.html', title = 'Register', form=form)



# Login/Logout
#####################################################################################
#####################################################################################

@app.route("/", methods = ['GET', 'POST'])
@app.route("/login", methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated and (current_user == 'user'):
        return redirect(url_for('user_page'))
    if current_user.is_authenticated and (current_user == 'admin'):
        return redirect(url_for('admin_home'))
    ## create variable form and make it call LoginForm() from the forms.py which holds requirements for the registration form
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and (user.user_type == 'admin'):
            login_user(user, remember = form.remember.data)
            ## next_page is a variable set to take the user to the page it originally tried to access but failed to do so incase they werent logged in
            next_page = request.args.get('next')
            ## turnary arguement, redirect to next_page if there was a next_page at the time if not take them straight to the home page
            return redirect(next_page) if next_page else redirect(url_for('admin_home'))
        elif user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember = form.remember.data)
            ## next_page is a variable set to take the user to the page it originally tried to access but failed to do so incase they werent logged in
            next_page = request.args.get('next')
            ## turnary arguement, redirect to next_page if there was a next_page at the time if not take them straight to the home page
            return redirect(next_page) if next_page else redirect(url_for('user_page', username = user.username))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title = 'Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('You have successfully been logged out', 'info')
    return redirect(url_for('home'))


# User Routes
#####################################################################################
#####################################################################################

@app.route("/user_page", methods = ['GET', 'POST'])
@login_required
def user_page():
    return render_template('user_page.html')

@app.route("/post/new", methods = ['GET', 'POST'])
@login_required
def create_post():
    form = QueueForm()
    if form.validate_on_submit():
        post = Post(title = form.title.data, content = form.content.data, category = form.category.data, status = status[0], author = current_user)
        print('***********************************************************************', 'Category: ',form.content, 'Content: ',form.content.data)
        db.session.add(post)
        db.session.commit()
        flash('You are now in line for help desk support!', 'success')
        return redirect(url_for('in_queue'))
    return render_template('create_post.html', title = 'Get in line', form = form, legend = 'How can we help you?')

@app.route("/in_queue", methods = ['GET', 'POST'])
@login_required
def in_queue():
    count = "5"
    return render_template('in_queue.html', count = count)


@app.route("/user/<string:username>")
def user_posts(username):
    ## paginate is used here to show a certain amount of posts per page
    action = PageAction()
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(username = username).first_or_404()
    print(user.username)
    posts = Post.query.filter_by(author = user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page = page, per_page = 5)
    ## render_template is the function that points at the html you want to direct the route to, you can add a variable in the arguements to be used within the html using jinja
    return render_template('user_posts.html', posts = posts, user = user, status = status, action = action, filter_status = 'open')


@app.route("/user/<string:username>/open")
def user_posts_open(username):
    ## paginate is used here to show a certain amount of posts per page
    action = PageAction()
    print(PageAction().filter_by)
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(username = username).first_or_404()
    posts = Post.query.filter_by(author = user, status = status[0])\
        .order_by(Post.date_posted.desc())\
        .paginate(page = page, per_page = 5)
    if posts.total == 0:
        flash('You currently have no open tickets', 'info')
   ## render_template is the function that points at the html you want to direct the route to, you can add a variable in the arguements to be used within the html using jinja
    return render_template('user_posts.html', posts = posts, user = user, status = status, action = action)


@app.route("/user/<string:username>/assisting")
def user_posts_assisting(username):
    ## paginate is used here to show a certain amount of posts per page
    action = PageAction()
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(username = username).first_or_404()
    posts = Post.query.filter_by(author = user, status = status[1])\
        .order_by(Post.date_posted.desc())\
        .paginate(page = page, per_page = 5)
    if posts.total == 0:
        flash('You currently have no one assisting your tickets', 'info')

   ## render_template is the function that points at the html you want to direct the route to, you can add a variable in the arguements to be used within the html using jinja
    return render_template('user_posts.html', posts = posts, user = user, status = status, action = action)


@app.route("/user/<string:username>/complete")
def user_posts_complete(username):
    ## paginate is used here to show a certain amount of posts per page
    action = PageAction()
    print(PageAction().filter_by)
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(username = username).first_or_404()
    posts = Post.query.filter_by(author = user, status = status[2])\
        .order_by(Post.date_posted.desc())\
        .paginate(page = page, per_page = 5)
    if posts.total == 0:
        flash('You currently have no completed tickets', 'info')
   ## render_template is the function that points at the html you want to direct the route to, you can add a variable in the arguements to be used within the html using jinja
    return render_template('user_posts.html', posts = posts, user = user, status = status, action = action)


@app.route("/user/<string:username>/canceled")
def user_posts_canceled(username):
    ## paginate is used here to show a certain amount of posts per page
    action = PageAction()
    print(PageAction().filter_by)
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(username = username).first_or_404()
    posts = Post.query.filter_by(author = user, status = status[3])\
        .order_by(Post.date_posted.desc())\
        .paginate(page = page, per_page = 5)
    if posts.total == 0:
        flash('You currently have no canceled tickets', 'info')
   ## render_template is the function that points at the html you want to direct the route to, you can add a variable in the arguements to be used within the html using jinja
    return render_template('user_posts.html', posts = posts, user = user, status = status, action = action)


# Admin Routes
#####################################################################################
#####################################################################################


@app.route("/admin", methods = ['GET', 'POST'])
@login_required
def admin_home():
    if current_user.user_type == 'admin':
        return render_template('admin_home.html')
    else:
        flash('You are unautorized to access this page', 'danger')
        return redirect(url_for('home'))


# Need logic for filter buttons
@app.route("/admin/user_posts", methods = ['GET', 'POST'])
@login_required
def admin():
    if current_user.user_type == 'admin':
        ## paginate is used here to show a certain amount of posts per page
        page = request.args.get('page', 1, type = int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page = page, per_page = 5)
        return render_template('admin.html', posts = posts, status = status)
    else:
        flash('You are unautorized to access this page', 'danger')
        return redirect(url_for('home'))

## Need to create reports html and logic
@app.route("/admin/reports", methods = ['GET', 'POST'])
@login_required
def reports():
    if current_user.user_type == 'admin':
        ## paginate is used here to show a certain amount of posts per page
        page = request.args.get('page', 1, type = int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page = page, per_page = 5)
        return render_template('reports.html')
    else:
        flash('You are unautorized to access this page', 'danger')
        return redirect(url_for('home'))

## Need to create user_accounts html and logic
@app.route("/admin/user_accounts", methods = ['GET', 'POST'])
@login_required
def user_accounts():
    pass


@app.route("/post/<int:post_id>", methods = ['GET', 'POST'])
@login_required
def post(post_id):
    admin = 'admin'
    form = QueueForm()
    action = PageAction()
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST' and (current_user.user_type == 'admin'):
        post.status = status[2]
        post.notes = form.notes.data
        post.assisted_by = current_user.username
        db.session.commit()   
        flash('Case has been completed', 'success')
        return redirect(url_for('admin'))
    return render_template('post.html', title = post.title, post = post, admin = admin, status = status, form = form, action = action)


@app.route("/post/<int:post_id>/assist", methods = ['GET', 'POST'])
@login_required
def assist_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = QueueForm()
    if current_user.user_type != 'admin':
        abort(403)
    post.status = status[1]
    post.assisted_by = current_user.username
    db.session.commit()
    flash('Status changed to assisting', 'success')
    return redirect(url_for('post', post_id = post.id, form = form))
    #return redirect(url_for('admin', form = form))


@app.route("/post/<int:post_id>/cancel", methods = ['POST'])
@login_required
def cancel_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.user_type == 'admin':
        post.status = status[3]
        post.assisted_by = current_user.username
        post.notes = f'Manually canceled by {current_user.username}'
        db.session.commit()   
        flash('Case has been canceled', 'danger')
        return redirect(url_for('admin'))