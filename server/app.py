#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    bio = data.get('bio')
    image_url = data.get('image_url')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 422

    try:
        new_user = User(
            username=username,
            bio=bio,
            image_url=image_url
        )
        new_user.password = password  # Hash the password here

        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.to_dict()), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username must be unique'}), 409  # Handle unique constraint violation
    except Exception as e:
        db.session.rollback()
        print(f"Error occurred: {str(e)}")  # Log the full error message
        return jsonify({'error': 'Failed to create user'}), 500


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
            else:
                return {"error": "User not found"}, 404
        return {"error": "Unauthorized. No active session."}, 401

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate_password(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None)
            return '', 204
        return jsonify({"error": "User is not logged in."}), 401

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session:
            recipes = Recipe.query.all()
            recipes_data = [
                {
                    "title": recipe.title,
                    "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user": {
                        "id": recipe.user.id,
                        "username": recipe.user.username,
                        "image_url": recipe.user.image_url,
                        "bio": recipe.user.bio
                    }
                }
                for recipe in recipes
            ]
            return jsonify(recipes_data), 200
        return jsonify({"error": "Unauthorized. Please log in to view recipes."}), 401
    
    def post(self):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        json_data = request.get_json()
        title = json_data.get('title')
        instructions = json_data.get('instructions')
        minutes_to_complete = json_data.get('minutes_to_complete')

        if not title or not instructions or not isinstance(minutes_to_complete, int):
            return jsonify({"error": "Invalid input data"}), 422

        new_recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=session['user_id']
        )

        db.session.add(new_recipe)
        db.session.commit()

        recipe_data = {
            "id": new_recipe.id,
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete,
            "user": {
                "id": new_recipe.user.id,
                "username": new_recipe.user.username,
                "image_url": new_recipe.user.image_url,
                "bio": new_recipe.user.bio,
            }
        }

        return jsonify(recipe_data), 201
    

api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
