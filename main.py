import re
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginUser, RegisterUser, CommentForm
from flask_gravatar import Gravatar


def purge(html_text):
    html_text = html_text.replace("\n", "reserved_for_new_line")

    script_elements = re.findall(
        r"<script.*script>", html_text, re.IGNORECASE)
    iframe_elements = re.findall(
        r"<iframe.*iframe>", html_text, re.IGNORECASE)

    for script_element in script_elements:
        html_text = html_text.replace(
            script_element, "<!-- " + script_element + " -->")

    for iframe_element in iframe_elements:
        html_text = html_text.replace(
            iframe_element, "<!-- " + iframe_element + " -->")

    html_text = html_text.replace("reserved_for_new_line", "\n")

    return html_text


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            return render_template("403.html"), 403
        elif not current_user.is_anonymous:
            if not current_user.is_admin:
                return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author =relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).filter(User.id == user_id).first()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUser()
    if form.validate_on_submit():
        email = form.email.data
        if db.session.query(User).filter(User.email == email).first() == None:
            is_admin = False
            if db.session.query(User).count() == 0:
                is_admin = True
            user = User(name=form.name.data, email=form.email.data, is_admin=is_admin, password=generate_password_hash(form.password.data, salt_length=8))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash("You've already signed with that email, log in instead!")
            return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.email == form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password incorrect, please try again.")
                return render_template("login.html", form=form)
        else:
            flash("That email does not exist, please try again.")
            return render_template("login.html", form=form)
    else:
        return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form_comment = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if requested_post:
        if form_comment.validate_on_submit():
            if not current_user.is_anonymous:
                new_comment = Comment(
                    author_id = current_user.id,
                    post_id = post_id,
                    text= purge(form_comment.comment.data)
                )
                db.session.add(new_comment)
                db.session.commit()
                form_comment.comment.data = None
            else:
                flash("You need login or register to comment.")
                return redirect(url_for("login"))
        return render_template("post.html", post=requested_post, form=form_comment)
    else:
        return redirect(url_for('get_all_posts'))

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")
    


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=purge(form.body.data),
            img_url=form.img_url.data,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if post:
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form)
    else:
        return redirect(url_for('get_all_posts'))


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if post_to_delete:
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
