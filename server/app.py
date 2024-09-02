from flask import request, session, jsonify
from flask_restful import Resource, Api
from werkzeug.security import generate_password_hash, check_password_hash
from config import app, db
from models import User

app.secret_key = b'a\xdb\xd2\x13\x93\xc1\xe9\x97\xef2\xe3\x004U\xd1Z'
api = Api(app)

class Signup(Resource):
    def post(self):
        json = request.get_json()

        if not json:
            return {"error": "Missing JSON body"}, 400
        if 'username' not in json or 'password' not in json:
            return {"error": "Missing username or password"}, 400

        if User.query.filter_by(username=json['username']).first():
            return {"error": "Username already exists"}, 400

        user = User(username=json['username'])
        user.password_hash = generate_password_hash(json['password'])
        
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify(user.to_dict()), 200
        
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()

        if not json:
            return {"error": "Missing JSON body"}, 400
        if 'username' not in json or 'password' not in json:
            return {"error": "Missing username or password"}, 400

        user = User.query.filter_by(username=json['username']).first()

        if user and user.authenticate(json['password']):
            session['user_id'] = user.id
            return jsonify(user.to_dict()), 200  # This should now include 'username'
        else:
            return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.clear()
            return {}, 204
        return {"error": "No active session found"}, 400

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')

if __name__ == '__main__':
    app.run(port=5555, debug=True)

