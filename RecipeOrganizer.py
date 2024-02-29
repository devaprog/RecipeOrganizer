import random
import string
import click
import cmd
import passlib
from sqlalchemy import create_engine, Column, Integer, String, Text, MetaData, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship

# Connect to SQLite database
engine = create_engine("sqlite:///recipe_organizer.db")
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(255), nullable=False, default="Viewer")

class Recipe(Base):
    __tablename__ = "recipes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    ingredients = Column(Text)
    instructions = Column(Text)
    notes = Column(Text)
    cuisine = Column(String(255))
    category = Column(String(255))
    user_id = Column(Integer, nullable=False)
    user = relationship(User, backref="recipes")

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()

def signup(username, password):
    if session.query(User).filter_by(username=username).first():
        print("Username already exists. Please choose another one.")
        return

    password_hash = passlib.hash.bcrypt.hash(password)
    user = User(username=username, password_hash=password_hash)
    session.add(user)
    session.commit()
    print("Signup successful!")

def forgot_password(username):
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print("User not found.")
        return

    # Generate a new random password
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    user.password_hash = passlib.hash.bcrypt.hash(new_password)
    session.commit()

    print(f"A new password has been generated for {username}: {new_password}")


def get_username_from_storage():
    # You should implement this function to retrieve username from storage
    pass

def is_logged_in():
    return bool(get_username_from_storage())

def logout():
    # Clear the username from storage upon logout
    pass

def authenticate_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and passlib.hash.bcrypt.verify(password, user.password_hash):
        return True
    else:
        return False

def get_current_user():
    if is_logged_in():
        username = get_username_from_storage()
        return session.query(User).filter_by(username=username).first()
    else:
        return None

def is_allowed(action, recipe):
    user = get_current_user()
    if not user:
        return False
    if user.role == 'Admin':
        return True
    elif user.role == 'Editor':
        if action in ('edit', 'delete'):
            return recipe.user_id == user.id
        return True
    elif user.role == 'Viewer':
        return action in ('search', 'filter', 'rate')
    else:
        return False

def add_recipe(name, ingredients, instructions, notes, cuisine, category):
    if not is_allowed('create', None):
        print("You don't have permission to add recipes.")
        return

    # Hash the password before saving
    password_hash = passlib.hash.bcrypt.hash(password)

    user = User(username=username, password_hash=password_hash)
    session.add(user)

    recipe = Recipe(name=name, ingredients=ingredients, instructions=instructions, notes=notes, cuisine=cuisine, category=category, user=user)
    session.add(recipe)
    session.commit()
    print("Recipe added successfully!")

def get_recipe_by_id(recipe_id):
    return session.query(Recipe).filter_by(id=recipe_id).first()

def edit_recipe(recipe_id, name, ingredients, instructions, notes, cuisine, category):
    recipe = get_recipe_by_id(recipe_id)
    if recipe and is_allowed('edit', recipe):
        recipe.name = name
        recipe.ingredients = ingredients
        recipe.instructions = instructions
        recipe.notes = notes
        recipe.cuisine = cuisine
        recipe.category = category
        session.commit()
        print("Recipe edited successfully!")
    else:
        print("Recipe not found or you don't have permission to edit it.")

def delete_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe and is_allowed('delete', recipe):
        session.delete(recipe)
        session.commit()
        print("Recipe deleted successfully!")
    else:
        print("Recipe not found or you don't have permission to delete it.")

# ... similarly define functions for other actions ...

class RecipeOrganizerCmd(cmd.Cmd):
    intro = "Welcome to the Recipe Organizer CLI!"
    prompt = ">Say> "

    def do_signup(self, arg):
        username, password = arg.split(',')
        signup(username, password)

    def do_forgot_password(self, arg):
        forgot_password(arg)

    def do_add(self, arg):
        args = arg.split(',')
        name = args[0].strip()
        ingredients = ','.join(args[1:-5]).strip()
        instructions = args[-5].strip()
        notes = args[-4].strip()
        cuisine = args[-3].strip()
        category = args[-2].strip()
        add_recipe(name, ingredients, instructions, notes, cuisine, category)

    def do_edit(self, arg):
        recipe_id, name, ingredients, instructions, notes, cuisine, category = arg.split(',')
        edit_recipe(int(recipe_id), name, ingredients, instructions, notes, cuisine, category)

    def do_delete(self, arg):
        delete_recipe(int(arg))

    def do_search(self, arg):
        recipes = session.query(Recipe).filter(Recipe.name.like(f"%{arg}%")).all()
        # Display search results

    def do_exit(self, arg):
        logout()
        session.close()
        print("Exiting...")
        return True

if __name__ == "__main__":
    RecipeOrganizerCmd().cmdloop()
