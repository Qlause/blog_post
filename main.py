from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import CreatePostForm, CreateRegister, LogIn, CommentsForm
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['CKEDITOR_PKG_TYPE'] = 'full-all'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

# users table
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    
    #  relation to BlogPost table and populate author collumn 
    posts = relationship("BlogPost", back_populates="author")
    
    #  relation to Comments table and populate author collumn 
    comments = relationship("Comments", back_populates="author")

# posts table
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    # realtion to Users table and populate posts collumn
    author = relationship("Users", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    #  relation to Comments table and populate post collumn 
    comments = relationship("Comments", back_populates="post")

# comments table
class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    
    #  relation to Users table and populate comments collumn 
    author = relationship("Users", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    #  relation to Users table and populate comments collumn
    post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

#run one time
db.create_all()

# Funcs
# Return Current User 
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

# Decorative func that just allow admin to access
def admin_only(func):
    def for_admin(*args, **kwargs):
        if current_user.get_id() == '1':
            return func(*args, **kwargs)
        else:
            return "UNAUTHORIZED"
    for_admin.__name__ = func.__name__
    return for_admin

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['get', 'post'])
def register():
    form = CreateRegister()
    if form.validate_on_submit():
        email = form.email.data
        
        if not Users.query.filter_by(email=email).first():
            name = form.name.data
            password = generate_password_hash(form.password.data, 
                                              method= "pbkdf2:sha256:12", 
                                              salt_length= 8)
            user_to_add = Users(name=name, 
                               email=email,
                               password=password)
            db.session.add(user_to_add)
            db.session.commit()
            
            return redirect(url_for('get_all_posts'))
        else:
            flash("Email Already Registered, Please Log in instead.")
            return redirect(url_for('login'))
        
    return render_template("register.html", form=form)


@app.route('/login', methods=['post', 'get'])
def login():
    form = LogIn()
    if form.validate_on_submit():
        email = form.email.data
        user_to_login = Users.query.filter_by(email=email).first()
        
        if user_to_login:
            if check_password_hash(user_to_login.password, form.password.data):
                login_user(user_to_login)
                return redirect(url_for('get_all_posts'))
            
        flash('either your email or passord is wrong')
        return redirect('login')
    
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['post', 'get'])
def show_post(post_id):
    form = CommentsForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comments.query.filter_by(post=requested_post).all()
    if form.validate_on_submit():
        if not current_user.is_active:
            flash('You should Log in to Comments')
            return redirect("/login")
        
        comment_to_add = Comments(author=current_user,
                                  body=form.body.data,
                                  post=requested_post)
        db.session.add(comment_to_add)
        db.session.commit()
        return redirect(f"/post/{post_id}")
    
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['post', 'get'])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        post_to_add = BlogPost(title=form.title.data,
                               subtitle=form.subtitle.data,
                               body=form.body.data,
                               img_url=form.img_url.data,
                               author=current_user,
                               date=date.today().strftime("%B %d, %Y")
                                )
        db.session.add(post_to_add)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
