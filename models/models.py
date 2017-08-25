from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """
    Creates a User table
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(60), index=True, unique=True)
    name = db.Column(db.String(60), index=True, unique=True)
    password = db.Column(db.String(128))

    def __init__(self, name, email, password):
        self.email = email
        self.name = name
        self.password = password

    def save(self):
        """Save a user to the database.
        This includes creating a new user and editing one.
        """
        db.session.add(self)
        db.session.commit()


class ShoppingList(db.Model):
    """
    Create a shopping table
    """

    __tablename__ = 'shoppinglists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref=db.backref('shoppinglists', lazy='dynamic'))

    def __init__(self, name, user_id):
        """initialize with name."""
        self.name = name
        self.user_id = user_id

    def save(self):
        db.session.add(self)
        db.session.commit()

    # @staticmethod
    # def get_all():
    #     return ShoppingList.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class Item(db.Model):
    """
    Create item table
    """

    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True)
    shoppinglist_id = db.Column(db.Integer, db.ForeignKey('shoppinglists.id'))
    shoppinglist = db.relationship(
        'ShoppingList', backref=db.backref('items', lazy='dynamic'))
