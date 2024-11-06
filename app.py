from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
from werkzeug.utils import secure_filename
import datetime
from functools import wraps

 

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"

app.config['UPLOAD_FOLDER'] = './uploads'  # Folder for storing uploaded files
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 


db = SQLAlchemy(app)


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])






class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

# Error handlers for consistent JSON responses
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request', 'message': str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication credentials were not provided or are invalid.'}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found', 'message': 'The requested resource could not be found.'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred on the server.'}), 500

# Additional error handler for files exceeding the allowed size
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Payload Too Large', 'message': 'File exceeds the maximum allowed size of 2 MB'}), 413





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError as e:
            print(f'Token decode error: {e}')  # Log the error
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# File upload endpoint
@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    print(request.files)  # Log files
    if 'file' not in request.files:
        return jsonify({'error': 'Bad Request', 'message': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Bad Request', 'message': 'No file selected for uploading'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        return jsonify({'message': 'File successfully uploaded', 'file_path': file_path}), 201
    else:
        return jsonify({'error': 'Unsupported Media Type', 'message': 'Allowed file types are: ' + ', '.join(ALLOWED_EXTENSIONS)}), 415



@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})
    

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'error': 'Not Found', 'message' : 'No user found!'}), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):


    if not current_user.admin:
        return jsonify({'error': 'Forbidden', 'message' : 'Cannot perform that function!'}), 403
    
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')



    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'}), 201

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'error': 'Forbidden', 'message' : 'Cannot perform that function!'}), 403

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'error': 'Not Found', 'message' : 'No user found!'}), 404
    
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'error': 'Forbidden', 'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'error': 'Not Found', 'message' : 'No user found!'}), 404

    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token})  # Remove .decode('UTF-8')

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/public/todos', methods=['GET'])
def get_public_todos():
    todos = Todo.query.filter_by(complete=False).all()  # Example filter for incomplete/public todos

    output = []
    for todo in todos:
        todo_data = {
            'id': todo.id,
            'text': todo.text,
            'complete': todo.complete
        }
        output.append(todo_data)

    return jsonify({'public_todos': output}), 200

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos' : output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'error': 'Not Found', 'message' : 'No todo found!'}), 404

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify(todo_data)

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : "Todo created!"}), 201


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'error': 'Not Found', 'message' : 'No todo found!'}), 404

    todo.complete = True
    db.session.commit()

    return jsonify({'message' : 'Todo item has been completed!'})


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'error': 'Not Found', 'message' : 'No todo found!'}), 404

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'Todo item deleted!'})


if __name__ == '__main__':
    app.run(debug=True)