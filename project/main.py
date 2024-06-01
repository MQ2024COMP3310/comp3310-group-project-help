from flask import (
  Blueprint, render_template, request, 
  flash, redirect, url_for, send_from_directory, 
  current_app, make_response, jsonify, json
)
from .models import Photo
from sqlalchemy import asc, text
from . import db
import os

main = Blueprint('main', __name__)

# This is called when the home page is rendered. It fetches all images sorted by filename.
@main.route('/')
def homepage():
  photos = db.session.query(Photo).order_by(asc(Photo.file))
  return render_template('index.html', photos = photos)

@main.route('/uploads/<name>')
def display_file(name):
  return send_from_directory(current_app.config["UPLOAD_DIR"], name)

# Upload a new photo
@main.route('/upload/', methods=['GET','POST'])
def newPhoto():
  if request.method == 'POST':
    file = None
    if "fileToUpload" in request.files:
      file = request.files.get("fileToUpload")
    else:
      flash("Invalid request!", "error")

    if not file or not file.filename:
      flash("No file selected!", "error")
      return redirect(request.url)

    filepath = os.path.join(current_app.config["UPLOAD_DIR"], file.filename)
    file.save(filepath)

    newPhoto = Photo(name = request.form['user'], 
                    caption = request.form['caption'],
                    description = request.form['description'],
                    file = file.filename)
    db.session.add(newPhoto)
    flash('New Photo %s Successfully Created' % newPhoto.name)
    db.session.commit()
    return redirect(url_for('main.homepage'))
  else:
    return render_template('upload.html')

# This is called when clicking on Edit. Goes to the edit page.
@main.route('/photo/<int:photo_id>/edit/', methods = ['GET', 'POST'])
def editPhoto(photo_id):
  editedPhoto = db.session.query(Photo).filter_by(id = photo_id).one()
  if request.method == 'POST':
    if request.form['user']:
      editedPhoto.name = request.form['user']
      editedPhoto.caption = request.form['caption']
      editedPhoto.description = request.form['description']
      db.session.add(editedPhoto)
      db.session.commit()
      flash('Photo Successfully Edited %s' % editedPhoto.name)
      return redirect(url_for('main.homepage'))
  else:
    return render_template('edit.html', photo = editedPhoto)


# This is called when clicking on Delete. 
@main.route('/photo/<int:photo_id>/delete/', methods = ['GET','POST'])
def deletePhoto(photo_id):
  fileResults = db.session.execute(text('select file from photo where id = ' + str(photo_id)))
  filename = fileResults.first()[0]
  filepath = os.path.join(current_app.config["UPLOAD_DIR"], filename)
  os.unlink(filepath)
  db.session.execute(text('delete from photo where id = ' + str(photo_id)))
  db.session.commit()
  
  flash('Photo id %s Successfully Deleted' % photo_id)
  return redirect(url_for('main.homepage'))

# Create a new album
@main.route('/albums/create', methods=['POST'])
def create_album():
    
    # Authenticate the user
    user = authenticate_user()
    if not user:
        # 401 Unauthorized: User must be authenticated
        response = make_response(json.dumps({"error": "Unauthorized"}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Validate the input
    album_name = request.json.get('name')
    if not album_name:
        # 400 Bad Request: Album name cannot be empty
        response = make_response(json.dumps({"error": "Album name cannot be empty"}), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Create the new album
    new_album = Album(user_id=user['id'], name=album_name)
    db.session.add(new_album)
    db.session.commit()
    
    # 201 Created: Album was successfully created
    response = make_response(json.dumps({"message": "Album created", "album": new_album.serialize()}), 201)
    response.headers['Content-Type'] = 'application/json'
    return response

# Add a photo to an album
@main.route('/albums/<int:album_id>/add_photo', methods=['POST'])
def add_photo_to_album(album_id):
   
    # Authenticate the user
    user = authenticate_user()
    if not user:
        # 401 Unauthorized: User must be authenticated
        response = make_response(json.dumps({"error": "Unauthorized"}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the album belongs to the authenticated user
    album = db.session.query(Album).filter_by(id=album_id, user_id=user['id']).one_or_none()
    if not album:
        # 404 Not Found: Album not found or not owned by user
        response = make_response(json.dumps({"error": "Album not found or not owned by user"}), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Validate the uploaded file
    file = request.files.get("fileToUpload")
    if not file or not file.filename:
        # 400 Bad Request: No file selected
        response = make_response(json.dumps({"error": "No file selected"}), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Save the file to the upload directory
    filepath = os.path.join(current_app.config["UPLOAD_DIR"], file.filename)
    file.save(filepath)

    # Create a new photo record
    new_photo = Photo(
        name=request.form.get('user', ''),
        caption=request.form.get('caption', ''),
        description=request.form.get('description', ''),
        file=file.filename,
        album_id=album_id
    )
    db.session.add(new_photo)
    db.session.commit()

    # 201 Created: Photo added to album
    response = make_response(json.dumps({"message": "Photo added to album", "photo": new_photo.serialize()}), 201)
    response.headers['Content-Type'] = 'application/json'
    return response

# View an album
@main.route('/albums/<int:album_id>', methods=['GET'])
def view_album(album_id):
    album = db.session.query(Album).filter_by(id=album_id).one_or_none()
    if not album:
        response = make_response(json.dumps({"error": "Album not found"}), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    photos = db.session.query(Photo).filter_by(album_id=album_id).all()
    return render_template('album.html', album=album, photos=photos)

# Edit an album
@main.route('/albums/<int:album_id>/edit', methods=['PUT'])
def edit_album(album_id):
    user = authenticate_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401  # Authentication check

    album = db.session.query(Album).filter_by(id=album_id, user_id=user['id']).one_or_none()
    if not album:
        return jsonify({"error": "Album not found or not owned by user"}), 404  # Authorization check

    album_name = request.json.get('name')
    if album_name:
        album.name = album_name  # Input validation

    db.session.add(album)
    db.session.commit()

    return jsonify({"message": "Album updated", "album": album.serialize()}), 200

# Delete an album
@main.route('/albums/<int:album_id>/delete', methods=['DELETE'])
def delete_album(album_id):
    user = authenticate_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401  # Authentication check

    album = db.session.query(Album).filter_by(id=album_id, user_id=user['id']).one_or_none()
    if not album:
        return jsonify({"error": "Album not found or not owned by user"}), 404  # Authorization check

    photos = db.session.query(Photo).filter_by(album_id=album_id).all()
    for photo in photos:
        filepath = os.path.join(current_app.config["UPLOAD_DIR"], photo.file)
        if os.path.exists(filepath):
            os.remove(filepath)  # Secure file handling
        db.session.delete(photo)

    db.session.delete(album)
    db.session.commit()

    return jsonify({"message": "Album and its photos deleted"}), 200

# Add a comment to a photo
@main.route('/photo/<int:photo_id>/comment', methods=['POST'])
def add_comment(photo_id):
    
    # Authenticate the user
    user = authenticate_user()
    if not user:
        # 401 Unauthorized: User must be authenticated
        response = make_response(json.dumps({"error": "Unauthorized"}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Validate the comment content
    content = request.json.get('content')
    if not content:
        # 400 Bad Request: Comment content cannot be empty
        response = make_response(json.dumps({"error": "Comment content cannot be empty"}), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Create a new comment
    new_comment = Comment(photo_id=photo_id, user_id=user['id'], content=content)
    db.session.add(new_comment)
    db.session.commit()

    # 201 Created: Comment was successfully added
    response = make_response(json.dumps({"message": "Comment added", "comment": new_comment.serialize()}), 201)
    response.headers['Content-Type'] = 'application/json'
    return response

# View comments for a photo
@main.route('/photo/<int:photo_id>/comments', methods=['GET'])
def view_comments(photo_id):
    comments = db.session.query(Comment).filter_by(photo_id=photo_id).all()
    serialized_comments = [comment.serialize() for comment in comments]
    return jsonify({"comments": serialized_comments}), 200

# Edit a comment
@main.route('/comment/<int:comment_id>/edit', methods=['PUT'])
def edit_comment(comment_id):
    user = authenticate_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401  # Authentication check

    comment = db.session.query(Comment).filter_by(id=comment_id, user_id=user['id']).one_or_none()
    if not comment:
        return jsonify({"error": "Comment not found or not owned by user"}), 404
        content = request.json.get('content')
    if content:
        comment.content = content  # Input validation

    db.session.add(comment)
    db.session.commit()

    return jsonify({"message": "Comment updated", "comment": comment.serialize()}), 200

# Delete a comment
@main.route('/comment/<int:comment_id>/delete', methods=['DELETE'])
def delete_comment(comment_id):
    user = authenticate_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401  # Authentication check

    comment = db.session.query(Comment).filter_by(id=comment_id, user_id=user['id']).one_or_none()
    if not comment:
        return jsonify({"error": "Comment not found or not owned by user"}), 404  # Authorization check

    db.session.delete(comment)
    db.session.commit()

    return jsonify({"message": "Comment deleted"}), 200

# TESTING

# Create Album Authentication Test
def test_create_album_unauthenticated(client):
    response = client.post('/albums/create', json={'name': 'New Album'})
    assert response.status_code == 401
    assert response.json['error'] == 'Unauthorized'

# Create Album Input Validation Test
def test_create_album_no_name(client, authenticated_user):
    response = client.post('/albums/create', json={}, headers=authenticated_user)
    assert response.status_code == 400
    assert response.json['error'] == 'Album name cannot be empty'

# Create Album SQL Injection Test 
def test_create_album_sql_injection(client, authenticated_user):
    response = client.post('/albums/create', json={'name': "'; DROP TABLE albums; --"}, headers=authenticated_user)
    assert response.status_code == 201
    assert 'album' in response.json

# Create Album XSS Test 
def test_create_album_xss(client, authenticated_user):
    xss_payload = '<script>alert("XSS")</script>'
    response = client.post('/albums/create', json={'name': xss_payload}, headers=authenticated_user)
    assert response.status_code == 201
    assert xss_payload not in response.json['album']['name']

