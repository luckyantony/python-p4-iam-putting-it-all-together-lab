from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)  # Removed nullable=False
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user', cascade='all, delete-orphan')

    serialize_rules = ('-recipes.user', '-_password_hash')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('password_hash is not a readable attribute')

    @password_hash.setter
    def password_hash(self, password):
        if password:
            self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        else:
            self._password_hash = None

    def authenticate(self, password):
        if self._password_hash is None:
            return False
        return bcrypt.check_password_hash(self._password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id')) 

    serialize_rules = ('-user.recipes',)

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError('Instructions must be at least 50 characters long')
        return instructions

    def __repr__(self):
        return f'<Recipe {self.title}>'