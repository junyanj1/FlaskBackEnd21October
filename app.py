import logging
from models import db, User, CompanyList
from flask import Flask, jsonify, request
from config import Config
from flask_httpauth import HTTPBasicAuth
from hashlib import sha256

app = Flask(__name__)
app.config.from_object(Config)
app.app_context().push()

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

auth = HTTPBasicAuth()

db.init_app(app)

db.create_all()

@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
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

@app.route('/api/token', methods=['GET', 'POST'])
@auth.login_required
def get_token():
    token = auth.current_user().generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

@app.route('/api/manageUsers/listUsers', methods=['GET'])
@auth.login_required(role='admin')
def list_all_users():
    users = User.query.all()
    response = {}
    for user in users:
        response[user.id] = {"username": user.username,
                             "role": user.role,
                             "permissions": user.permissions
                            }
    return response

@app.route('/api/manageUsers/createUser', methods=['POST'])
@auth.login_required(role='admin')
def create_new_user():
    # print(request.json)
    username = request.json.get('username')
    role = request.json.get('role')
    password = request.json.get('password')
    permissions = request.json.get('permissions')
    if None in [username, role, password, permissions]:
        return {"Error": "Invalid input, please make sure to have username, role, password and permissions"}, 401
    if User.query.filter_by(username=username).first() is not None:
        return {"Error": f"Invalid input, username {username} already exists"}, 409
    
    new_user = User(username=username)
    new_user.set_password(password)
    new_user.set_role(role)
    new_user.set_permissions(','.join(permissions))
    new_user.create_entry()
    u = User.query.filter_by(username=username).first()
    return {"Success": {"id": u.id, "username": u.username, "role": u.role, "permissions": u.permissions}}

@app.route('/api/manageUsers/updateUser', methods=['POST'])
@auth.login_required(role='admin')
def update_user():
    uid = request.json.get('id')
    username = request.json.get('username')
    if uid is None and username is None:
        return {"Error": "require either user id or username to make updates. "}, 400
    u = None
    if uid is not None:
        u = User.query.filter_by(id=uid).first()
    if u is None:
        u = User.query.filter_by(username=username).first()

    if u is None:
        return {"Error": f"the input id: {uid} and username: {username} cannot match any user on record."}, 404
    
    password = request.json.get('password')
    role = request.json.get('role')
    permissions = request.json.get('permissions')
    
    if password is not None:
        u.set_password(password)
    if role is not None:
        u.set_role(role)
    if permissions is not None:
        u.set_permissions(','.join(permissions))
    db.session.commit()
    
    u = None
    if uid is not None:
        u = User.query.filter_by(id=uid).first()
    if u is None:
        u = User.query.filter_by(username=username).first()
    return {"Success": {"id": u.id, "username": u.username, "role": u.role, "permissions": u.permissions}}


@app.route('/api/manageUsers/deleteUser', methods=['DELETE'])
@auth.login_required(role='admin')
def delete_user():
    uid = request.json.get('id')
    username = request.json.get('username')
    if uid is None and username is None:
        return {"Error": "require either user id or username to delete user. "}, 400
    u = None
    if uid is not None:
        u = User.query.filter_by(id=uid).first()
    if u is None:
        u = User.query.filter_by(username=username).first()

    if u is None:
        return {"Error": f"the input id: {uid} and username: {username} cannot match any user on record."}, 404
    
    u.delete_entry()
    if User.query.filter_by(id=u.id).count() != 0:
        return {"Error": f"Deleting user with id: {u.id} and username: {u.username} failed because of internal error. Please try again."}, 500
    else:
        return {"Success": f"successfully deleted user with id: {u.id} and username: {u.username}"}

@app.route("/api/CompanyLists/create", methods=["POST"])
@auth.login_required(role="admin")
def create_company_list():
    new_list = request.json.get('company_list')
    if new_list is None:
        return {"Error": "Input not containing the company_list field, please try again."}, 400
    new_company_list = CompanyList()
    new_company_list.set_company_list([str(i) for i in new_list])
    new_company_list.create_entry()
    cl = CompanyList.query.filter_by(id=new_company_list.id).first()
    return {"Success": {"id": cl.id, "CompanyList": [cl.company_list.split(",")]}}


@app.route('/api/CompanyLists/list', methods=['GET'])
@auth.login_required(role=['admin','user'])
def list_company_lists():
    user = auth.current_user()
    if user.role != 'admin':
        permissions = user.get_permissions().split(',')
        if 'company_list' not in permissions:
            return {'Error': 'User does not have permission to company lists.'}, 401
    company_lists = CompanyList.query.all()
    response = {}
    for cl in company_lists:
        response[cl.id] = {'company_list': cl.company_list}
    return response


@app.route('/api/CompanyLists/delete', methods=['DELETE'])
@auth.login_required(role='admin')
def delete_company_list():
    clid = request.json.get('id')
    if clid is None:
        return {'Error': 'The request body does not have field id. Please try again.'}, 400
    cl = CompanyList.query.filter_by(id=clid).first()
    if cl is None:
        return {'Error': f'The requested id {clid} cannot be found.'}, 404
    cl.delete_entry()
    if CompanyList.query.filter_by(id=cl.id).count() != 0:
        return {"Error": f"Deleting company list with id: {cl.id} failed because of internal error. Please try again."}, 500
    else:
        return {"Success": f"successfully deleted company list with id: {cl.id} and content: {cl.company_list}"}

@app.route("/api/userCompanyListAssociation/create", methods=["POST"])
@auth.login_required(role='admin')
def create_association():
    uid = request.json.get('userId')
    clid = request.json.get('companyListId')
    if None in [uid, clid]:
        return {'Error': 'Missing required fields userId or/and companyListId in the body.'}, 400
    cl = CompanyList.query.filter_by(id=clid).first()
    if cl is None:
        return {'Error': f'Invalid company list id {clid}.'}, 404
    u = User.query.filter_by(id=uid).first()
    if u is None:
        return {'Error': f'Invalid user id {uid}.'}, 404
    u.user_company_list.append(cl)
    db.session.commit()
    return {'Success': f'Added association for user with id: {u.id} and username: {u.username} with company list: {cl.company_list}'}

@app.route('/api/userCompanyListAssociation/read/<uid>', methods=['GET'])
@auth.login_required(role='admin')
def list_associations(uid):
    if uid is None:
        return {'Error': 'Missing user id in the path route.'}, 400
    u = User.query.filter_by(id=uid).first()
    if u is None:
        return {'Error': f'The given user id {uid} cannot be found.'}, 404
    response = {}
    for cl in u.user_company_list:
        response[cl.id] = cl.company_list
    return response

@app.route('/api/userCompanyListAssociation/delete', methods=['DELETE'])
@auth.login_required(role='admin')
def delete_associations():
    uid = request.json.get('userId')
    clid = request.json.get('companyListId')
    if None in [uid, clid]:
        return {'Error': 'Missing field userId and/or companyListId in the body.'}, 400
    u = User.query.filter_by(id=uid).first()
    if u is None:
        return {'Error': f'User with id: {uid} cannot be found.'}, 404
    cl = CompanyList.query.filter_by(id=clid).first()
    if cl is None:
        return {'Error': f'Company list with id: {clid} cannot be found.'}, 404
    u.user_company_list.remove(cl)
    db.session.commit()
    return {'Success': f'removed company list with id: {cl.id} and list: {cl.company_list}, '+
                       f'from user with id: {u.id} and username: {u.username}'
           }

@app.route('/api/viewCompany/<company_id>', methods=['GET'])
@auth.login_required(role='user')
def view_company(company_id):
    user = auth.current_user()
    permissions = user.get_permissions().split(',')
    if 'company_info' not in permissions:
        return {'Error': f'The current user with id: {user.id} and username: {user.username} does not have "company_info" permission.'}, 401

    return {'Company info': sha256(str(company_id).encode('utf-8')).hexdigest()}

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')