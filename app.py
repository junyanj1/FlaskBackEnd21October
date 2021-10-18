import logging
from models import db, User
from flask import Flask
from config import Config
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
app.config.from_object(Config)
app.app_context().push()

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

auth = HTTPBasicAuth()

db.init_app(app)

db.create_all()

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return None
    return user

@auth.get_user_roles
def get_user_roles(user):
    return user.get_role()

######### Testing ##########
if User.query.filter_by(username='jj').count() == 0:
    jj = User('jj')
    jj.set_role('admin')
    jj.set_password('SomeSecretPassword')
    jj.add_permission('company_list')
    jj.create_entry()

if User.query.filter_by(username='uu').count() == 0:
    uu = User('uu')
    uu.set_role('user')
    uu.set_password('SomeSecretPassword')
    uu.add_permission('company_list')
    uu.create_entry()

@app.route('/resources/')
@auth.login_required(role = 'admin')
def resources():
    print(auth.current_user())
    return {"username": auth.current_user().username, "permissions": auth.current_user().permissions}


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')