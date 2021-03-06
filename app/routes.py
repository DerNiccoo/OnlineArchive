from flask import render_template, flash, redirect, url_for
from flask import Flask, render_template, redirect, request, Markup, jsonify, escape, make_response, session, url_for
from flask import send_from_directory
from flask_uploads import UploadSet, configure_uploads, IMAGES, DOCUMENTS, patch_request_class


from app import app
from app import img_upload
from app import db
#from app.forms import LoginForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import Account, Account_permission, Permission, Image, Image_Text, ImageQuery, Image_TextQuery, AccountQuery, PermissionQuery, Account_permissionQuery, FilterQuery, Account_FilterQuery, Account_RankQuery, RankQuery
from app.forms import RegistrationForm, ChangePasswordForm
from app.thumbnail_image import create_thumbnail

import os
import time
import datetime
from shutil import copyfile

locked_filters = [0, 3, 4, 5]

@app.route("/")
def index():
  session['file_urls'] = []
  return render_template('overview.html', current_user = current_user)

@app.route("/contact")
def contact():
  return render_template("contact.html")

@app.route("/impressum")
def impressum():
  return render_template("impressum.html")

@app.route("/agb")
def agb():
  return render_template("agb.html")

@app.route("/search/<string:search>", methods=['GET', 'POST'])
def search_images(search):
  return render_template('overview.html', current_user = current_user)

@app.route("/Upload", methods=['GET', 'POST'])
@login_required
def template_upload():
  # TODO: /upload & /confirm_upload ändern. Sodass /upload die Daten nur in einen Temporären ordner speichert, und die ERST NACH BESTÄTIGEN in das richtige System übernommen werden
  # Hier werden die Bilder einfach auch DIREKT hochgeladen. Dazu werden die aber einfach auf "unsichtbar" gestellt und ERST wenn der User die TAG form bestaetigt wird das wieder geaendert und die Bilder koennen eingesehen werden

  if "content_upload" not in current_user.permissions_name:
    return redirect(url_for("index"))

  if "file_urls" not in session:
    session['file_urls'] = []

  # list to hold our uploaded image urls
  file_urls = session['file_urls'] 
  if request.method == 'POST':
    file_obj = request.files
    for f in file_obj:
      file = request.files.get(f)
      
      file_type = file.filename.split('.')[1].lower()  
      num_files = ImageQuery.upload_image(current_user.username, 0, file_type) 
      
      file_filename = f'{num_files}.{file_type}'
      full_name = os.getcwd() + f'/app/thumb/{file_filename}'
      print(file_filename)

      filename = img_upload.save(
          file,
          name=f'{num_files}.{file_type}'    
      )        

      if file_type != "pdf":
        create_thumbnail(file, full_name)
        file_urls.append(f'content/thumb/{file_filename}')
      else:
        copyfile(os.getcwd() + '/app/static/images/thumb/pdf.png', os.getcwd() + f'/app/thumb/{num_files}.png')    
        file_urls.append(f'content/thumb/{num_files}.png')
        
    session['file_urls'] = file_urls
    return "uploading..."    # return dropzone template on GET request    

  return render_template('upload.html', current_user = current_user)

@app.route("/load")
def load():
    """ Route to return the posts """

    quantity = 9 * 13

    if request.args:
      searchList = create_search_term(request.args.get("s"))
      user_filter = get_user_filter()

      files, img_filters = ImageQuery.get_available_images(searchList, user_filter)
      num_files = len(files)
      
      counter = int(request.args.get("c"))  # The 'counter' value sent in the QS

      action = "more"
      filters = []

      if counter == 0:
          # Slice 0 -> quantity from the db
          db = []
          
          available = quantity
          if quantity > num_files:
            available = num_files
            action = "last"          

          for x in range(num_files - 1, num_files - available - 1, -1):
            filters.append(img_filters[x])
            if os.path.exists(os.getcwd() +  f"/app/thumb/{files[x]}.jpg"):
              db.append(f"/content/thumb/{files[x]}.jpg")
            else:
              db.append(f"/content/thumb/{files[x]}.png")

          res = make_response(jsonify(action = action, images = db, filters = filters), 200)

      elif counter >= num_files:
          res = make_response(jsonify(action = "end"), 200)

      else:
          # Slice counter -> quantity from the db
          db = []

          limit = counter + quantity
          if limit > num_files:
            limit = num_files
            action = "last" 

          for x in range(num_files - counter, num_files - limit, -1):
            filters.append(img_filters[x])
            if os.path.exists(os.getcwd() +  f"/app/thumb/{files[x]}.jpg"):
              db.append(f"/content/thumb/{files[x]}.jpg")
            else:
              db.append(f"/content/thumb/{files[x]}.png")

          res = make_response(jsonify(action = action, images = db, filters = filters), 200)

    return res

@app.route("/confirm_upload", methods=['POST'])
@login_required
def confirm_upload():
  if "content_upload" not in current_user.permissions_name:
    return redirect(url_for("index"))

  if "file_urls" not in session or session['file_urls'] == []:
    return redirect(url_for('index'))

  file_urls = session['file_urls']
  session.pop('file_urls', None)

  tags, duplicates = tags_to_list(request.form.get('tags'))
  img_filter = request.form.get("filter")
  
  if img_filter == None:
    img_filter = 0

  for path in file_urls:
    img_id = path.split('/')[2].split('.')[0]
    if "content_confirm" in current_user.permissions_name:
      ImageQuery.change_img_filter(img_id, img_filter)

    for tag in tags:
      image_Text = Image_Text(img_id, tag, current_user.username)
      db.session.add(image_Text)

  db.session.commit()
  return redirect(url_for('index'))

@app.route("/img/<string:img_ID>", methods=['GET', 'POST'])
def show_img(img_ID):
  #TODO: This just loads the page, nothing with path
  imgPath = f"../content/img/{img_ID}.jpg"
  filters = FilterQuery.get_all_filters_above_value(1)
  return render_template('imageView.html', imgPath = imgPath, current_user = current_user, filters = filters)

@app.route("/data", methods=['POST'])
def get_item_data():
  img_id = int(request.form['item'])
  typ = request.form['action']
  user_filter = get_user_filter()

  if typ == 'next':
    new_img_id = ImageQuery.get_new_image(img_id, True, user_filter) #TODO: Das hier könnte optimiert werden, da hier bereits das ganze Bild geladen wird
  elif typ == 'prev':
    new_img_id = ImageQuery.get_new_image(img_id, False, user_filter)
  else:
    new_img_id = img_id

  all_tags = Image_TextQuery.get_tags_to_image(new_img_id)
  image_info = ImageQuery.get_image_information(new_img_id)
  
  return jsonify(author= image_info.username, time= image_info.upload_time, img_filter = image_info.filter, image= f"/content/img/{new_img_id}.{image_info.datatype}", id=new_img_id, tags=all_tags)

@app.route("/addTag", methods=['POST'])
@login_required
def add_Tag_to_image():
  if "tags_create" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  img_tags = Image_TextQuery.get_tags_to_image(request.form['image'])
  raw_tags, duplicates = tags_to_list(request.form['tags'], img_tags)
  new_tags = []

  for tag in raw_tags:
    image_Text = Image_Text(request.form['image'], tag, current_user.username)
    db.session.add(image_Text)
    new_tags.append(tag)

  db.session.commit()

  if duplicates == 0:
    return jsonify(action="success")
  else:
    if duplicates > 1:
      return jsonify(action="success", error= f'{duplicates} Tags wurden übersprungen.')
    else:
      return jsonify(action="success", error= f'{duplicates} Tag wurde übersprungen.')

@app.route("/removeTag", methods=['POST'])
@login_required
def remove_tag_from_image():  
  if "tags_remove" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  Image_TextQuery.remove_tag(request.form['item'], request.form['tag'])
  return make_response(jsonify(action="success"), 200)

@app.route('/results')
@login_required
def results():
  if "content_upload" not in current_user.permissions_name:
    return redirect(url_for("index"))
  
  # redirect to home if no images to display
  if "file_urls" not in session or session['file_urls'] == []:
    return redirect(url_for('index'))
    
  # set the file_urls and remove the session variable
  file_urls = session['file_urls']
  
  filters = FilterQuery.get_all_filters_above_value(1)

  return render_template('results.html', file_urls=file_urls, current_user = current_user, filters = filters)

@app.route('/content/<path:filename>')
def get_content(filename):
  img_id = filename.split("/")[-1].split(".")[0]
  img_info = ImageQuery.get_image_information(img_id)

  if 'thumb' in filename:
    return send_from_directory("", filename)

  if img_info.filter > 1:
    if current_user.is_authenticated: 
      if img_info.filter not in get_user_filter(): 
        return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401) 
    else:
      return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)
  return send_from_directory("", filename)

@app.route('/login', methods=['POST'])
def login():
  if current_user.is_authenticated:
      return redirect(url_for('index'))
  
  username = request.form['username']
  password = request.form['password']

  user = AccountQuery.get_User(username)
  if user == None:
    return make_response(jsonify(action="failed", error="Nutzer nicht vorhanden!"), 200)  

  if user.check_password(password):
    login_user(user, remember=True)
    if user.default_pw:
      return make_response(jsonify(action="success", change_password = True), 200) 
    return make_response(jsonify(action="success"), 200)  
  else:
    return make_response(jsonify(action="failed", error="Ungültiges Passwort!"), 200)    

@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('index'))

@app.route('/filter', methods=['POST'])
@login_required
def filter():
  perm_name, _ = FilterQuery.get_permission_filters()
  all_filters = FilterQuery.get_all_filters()

  Account_FilterQuery.remove_user_filters(current_user.username)  

  for f in all_filters:
    if f.name in perm_name:
      if f.name not in current_user.permissions_name:
        continue
    if request.form.get(f.name):
      Account_FilterQuery.add_user_filters(current_user.id, f.id)

  return redirect(url_for('index'))

@app.route('/changeFilter', methods=['POST'])
@login_required
def changeFilter():
  if "filter_change" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  ImageQuery.change_img_filter(request.form['image'], request.form['filter'])
  return jsonify(action="success")

@app.route('/removeImage', methods=['POST'])
@login_required
def remove_image():
  if "content_remove" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  image_id = request.form["item"]
  Image_TextQuery.remove_tag(image_id)
  ImageQuery.remove_img(image_id)

  if os.path.exists("img/" + image_id + ".jpg"):
    os.remove("img/" + image_id + ".jpg")

  if os.path.exists("thumb/" + image_id + ".jpg"):
    os.remove("thumb/" + image_id + ".jpg")
  return make_response(jsonify(action="success"), 200)

@app.route('/user/<string:username>')
@login_required
def profile(username):
  profile_user = AccountQuery.get_User(username)
  profile_user.password_hash = None

  uploads = ImageQuery.count_uploads_from_user(profile_user.username)
  tags = Image_TextQuery.count_tags_from_user(profile_user.username)

  created_at = profile_user.created_at.strftime("%d.%m.%Y")
  diff = (datetime.datetime.now() - profile_user.created_at).days

  return render_template('profile.html', current_user = current_user, profile_user = profile_user, uploads=uploads, tags=tags, created_at=created_at, diff=diff) 

@app.route('/getPermissions', methods=['POST'])
@login_required
def get_permissions():
  if "allow_permission" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  user_permissions = AccountQuery.get_user_permissions(request.form['username'])
  permissions_query = PermissionQuery.get_permissions()
  permissions = []

  for p in permissions_query:
    permissions.append([p.name, p.label])
  
  return jsonify(action="success", permissions = permissions, user_permissions = user_permissions)


@app.route('/getRanks', methods=['POST'])
@login_required
def get_ranks():
  if "rank_change" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  user = AccountQuery.get_User(request.form['username'])
  if not user.rank_rel:
    user_rank = ""
  else:
    user_rank = user.rank_rel[0].rank_rel.name
    
  rank_query = RankQuery.get_all_ranks()
  ranks = []

  for r in rank_query:
    ranks.append([r.name, r.label])  

  return jsonify(action="success", ranks = ranks, user_rank = user_rank)

@app.route('/changePermission', methods=['POST'])
@login_required
def change_permission():
  if "allow_permission" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  username = request.form['username']
  permission = request.form['permission'] 
  permission_state = request.form['permission_state']
  
  perm = PermissionQuery.get_filter_permissions()
  if permission in perm and permission_state == "false":
    Account_FilterQuery.remove_user_filters(username)

  Account_permissionQuery.change_permission(current_user.username, username, permission, permission_state)

  return make_response(jsonify(action="success"), 200)

@app.route('/changeRank', methods=['POST'])
@login_required
def change_rank():
  if "rank_change" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)

  Account_RankQuery.remove_user_rank(request.form['username'])
  Account_RankQuery.add_user_rank(request.form['username'], request.form['rank'])

  return make_response(jsonify(action="success"), 200)

@app.route('/members')
@login_required
def members():
  return render_template('members.html', current_user = current_user)

@app.route('/getMembers', methods=['POST'])
@login_required
def get_members():
  all_accounts = AccountQuery.get_all_user()
  members = []

  for m in all_accounts:
    members.append([m.id, m.username, m.created_at])

  return make_response(jsonify(action="success", members = members), 200)

@app.route('/changePasswordForm', methods=['POST'])
@login_required
def changePasswordForm():
  form = ChangePasswordForm()
  return render_template('changePassword.html', form = form)

@app.route('/changePassword', methods=['POST'])
@login_required
def changePassword():
  form = ChangePasswordForm()
  form.username = current_user.username
  if form.validate_on_submit():
    AccountQuery.update_password(current_user.username, form.new_password.data)
    return jsonify(action="success")
  return jsonify(action="failed", error=form.errors)

@app.route('/registerForm', methods=['POST'])
@login_required
def registerForm():
  if "user_create" not in current_user.permissions_name:
    return redirect(url_for('index'))

  form = RegistrationForm()
  return render_template('register.html', form = form)

@app.route('/register', methods=['POST'])
@login_required
def register():
  if "user_create" not in current_user.permissions_name:
    return make_response(jsonify(action="failed", error="Fehlende Berechtigung"), 401)
    
  form = RegistrationForm()
  if form.validate_on_submit():
    AccountQuery.create_user(form.username.data, form.password.data)
    return jsonify(action="success", username=form.username.data)
  return jsonify(action="failed", error=form.errors)

@app.route('/filterForm', methods=['POST'])
@login_required
def filterForm():
  available_filters = FilterQuery.get_all_filters()
  locked_name, locked_value = FilterQuery.get_permission_filters()
  filters = []

  for f in available_filters:
    if f.value in locked_value:
      if f.name not in current_user.permissions_name:
        continue

    filters.append([f.value, f.name, f.label])

  return render_template('filter.html', filters = filters)

@app.route('/userFilter', methods=['POST'])
@login_required
def get_user_filter_form():
  user_filter = Account_FilterQuery.get_user_filters(current_user.id)
 
  if len(user_filter) == 0:
    user_filter.append(FilterQuery.get_filter_by_value(1))
    
  return make_response(jsonify(action="success", user_filter=user_filter))

def get_user_filter():
  if current_user.is_authenticated:
    return current_user._filter
  else:
    return (1, )

def tags_to_list(tags_string, existing_tags = []):
  tag_list = []
  duplicate = 0

  for tag in tags_string.split(','):
    if tag.strip() not in tag_list and tag.strip() not in existing_tags and not tag.isspace() and len(tag.strip()) > 1:
      tag_list.append(tag.strip())
    else:
      duplicate += 1

  return tag_list, duplicate

def create_search_term(searchTerm):
  if searchTerm == None:
    return None  
  
  searchList = []
  for s in searchTerm.split(' '):
    searchList.append(f'%{s}%')

  return searchList
