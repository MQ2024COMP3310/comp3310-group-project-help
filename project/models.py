from . import db

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    caption = db.Column(db.String(250), nullable=False)
    file = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(600), nullable=True)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'           : self.id,
           'name'         : self.name,
           'caption'      : self.caption,
           'file'         : self.file,
           'desc'         : self.description,
       }
        
 class Album(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)  # Assuming user ID is stored as integer
    name = db.Column(db.String(50), nullable=False)
    photos = db.relationship('Photo', backref='album', lazy=True)  # Relationship to photos

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'photos': [photo.serialize for photo in self.photos]
        }

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=False)  # Foreign key to Photo
    user_id = db.Column(db.Integer, nullable=False)  # Assuming user ID is stored as integer
    content = db.Column(db.String(500), nullable=False)
    photo = db.relationship('Photo', backref='comments', lazy=True)  # Relationship to photo

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'photo_id': self.photo_id,
            'user_id': self.user_id,
            'content': self.content,
        }
