from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import or_
from app import db
from app import login

@login.user_loader
def load_user(id):
  user = Account.query.get(int(id))
  user._filter = user.create_user_filter()
  user.permissions_name = user.set_permissions_name()
  return user

class Account(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(64), index=True, unique=True)
  password_hash = db.Column(db.String(128))
  filter = db.Column(db.Integer)
  created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  default_pw = db.Column(db.Boolean, default=True)
  permissions = db.relationship("Account_permission", back_populates="account")
  filter_rel = db.relationship("Account_Filter", back_populates="account_rel")
  permissions_name = []
  #permission_assigner = db.relationship("Account_permission", back_populates="assigner", lazy="dynamic")

  def __init__(self, username, password, filter):
    self.username = username
    self.set_password(password)
    self.filter = filter

  def set_password(self, password):
    self.password_hash = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password_hash, password)

  def __repr__(self):
    return '<Account {}>'.format(self.username)

  def create_user_filter(self):
    res = []

    for f in self.filter_rel:
      res.append(f.filter_rel.value)

    if len(res) == 0:
      res.append(1) # Filter with value 1 is default filter!!!

    return tuple(res)

  def set_permissions_name(self):
    names = []
    for p in self.permissions:
      names.append(str(p.permission.name))

    return names

class AccountQuery(object):
  @staticmethod
  def get_User(username):
    account = Account.query.filter(Account.username.ilike(username)).first()
    return account if hasattr(account, 'id') else None

  @staticmethod
  def get_all_user():
    account = Account.query.order_by(Account.id).all()
    return account
    
  @staticmethod
  def get_user_filter(username):
    account = Account.query.filter(Account.username.ilike(username)).first()
    return account.filter if hasattr(account, 'id') else None

  @staticmethod
  def update_filter(username, filter):
    account = Account.query.filter(Account.username.ilike(username)).first()
    account.filter = filter
    account._filter = account.create_user_filter()
    db.session.commit()
    return account

  @staticmethod
  def get_user_permissions(username):
    account = Account.query.filter(Account.username.ilike(username)).first()
    return account.set_permissions_name()

  @staticmethod
  def create_user(username, password):
    account = Account(username, password, 1)
    db.session.add(account)
    db.session.commit()
    return account  

  @staticmethod
  def update_password(username, password):
    account = Account.query.filter(Account.username.ilike(username)).first()
    account.set_password(password)
    account.default_pw = False
    db.session.commit()
    return account  

class Account_permission(db.Model):
  user_id = db.Column(db.Integer, db.ForeignKey('account.id'), primary_key=True)
  perm_id = db.Column(db.Integer, db.ForeignKey('permission.id'), primary_key=True)
  assigned_by = db.Column(db.String(64)) #, db.ForeignKey('account.username'))
  assigned_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  account = db.relationship("Account", back_populates="permissions", foreign_keys=[user_id])
  #assigner = db.relationship("Account", back_populates="permission_assigner", lazy="dynamic", foreign_keys=[assigned_by])
  permission = db.relationship("Permission", back_populates="perm")

  def __repr__(self):
    return f'<Acc_Perm id: {self.user_id} perm_id: {self.perm_id}>'

  def __init__(self, user_id, perm_id, assigned_by):
    self.user_id = user_id
    self.perm_id = perm_id
    self.assigned_by = assigned_by

class Account_permissionQuery(object):
  @staticmethod
  def change_permission(activ_username, username, permission, permission_state):
    if permission_state == "false":
      perm = Account_permission.query\
        .join(Permission, Permission.id == Account_permission.perm_id)\
        .join(Account, Account.id == Account_permission.user_id)\
        .filter(Account.username == username)\
        .filter(Permission.name == permission)\
        .filter(Permission.id == Account_permission.perm_id)\
        .first()

      db.session.delete(perm)
      db.session.commit()
    else:
      perm = Permission.query.filter(Permission.name == permission).first()
      account = Account.query.filter_by(username=username).first()
      acc_perm = Account_permission(account.id, perm.id, activ_username)
      db.session.add(acc_perm)
      db.session.commit()
    
    return True

class Image(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(64), db.ForeignKey('account.username'))
  filter = db.Column(db.Integer)
  upload_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  datatype = db.Column(db.String(5))
  image_Text = db.relationship("Image_Text", back_populates="image")

  def __init__(self, username, filter, datatype):
    self.username = username
    self.filter = filter
    self.datatype = datatype

class ImageQuery(object):
  @staticmethod
  def count_uploads_from_user(username):
    uploads_count = Image.query.filter_by(username=username).count()
    return uploads_count

  @staticmethod
  def get_available_images(search_items, user_filter):
    if search_items == None:
      images = Image.query.filter(Image.filter.in_(user_filter)).order_by(Image.id).all()
    else:
      cond = or_(*[Image_Text.tag.ilike(s) for s in search_items])
      images = Image.query\
        .join(Image_Text, Image_Text.id == Image.id)\
        .filter(Image.filter.in_(user_filter))\
        .filter(cond)\
        .order_by(Image.id).all()


    list_of_ids = [image.id for image in images]
    list_of_filters = [image.filter for image in images]

    return list_of_ids, list_of_filters

  @staticmethod
  def upload_image(username, img_filter, datatype):
    image = Image(username= username, filter= img_filter, datatype = datatype)

    db.session.add(image)
    db.session.commit()

    return image.id

  @staticmethod
  def remove_img(image_id):
    image = Image.query.get(image_id)
    db.session.delete(image)
    db.session.commit()
    return True

  @staticmethod
  def change_img_filter(image_id, imgFilter):
    image = Image.query.get(image_id)
    image.filter = imgFilter
    db.session.commit()

    return True

  @staticmethod
  def get_new_image(image_id, next_img, user_filter):
    image = Image.query.filter(Image.id < image_id, Image.filter.in_(user_filter)).order_by(Image.id.desc()).first()
    
    if not next_img:
      image = Image.query.filter(Image.id > image_id, Image.filter.in_(user_filter)).order_by(Image.id).first()

    return image.id

  @staticmethod
  def get_image_information(image_id):
    image = Image.query.filter_by(id=image_id).first()
    return image if hasattr(image, 'id') else None

class Permission(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(128))
  label = db.Column(db.String(128))
  perm = db.relationship("Account_permission", back_populates="permission")

class PermissionQuery(object):
  @staticmethod
  def get_permissions():
    permissions = Permission.query.order_by(Permission.label).all()
    return permissions 

  @staticmethod
  def get_filter_permissions():
    permissions = Permission.query.filter(Permission.name.ilike('%filter%'))
    return [p.name for p in permissions]

class Image_Text(db.Model):
  id = db.Column(db.Integer, db.ForeignKey('image.id'), primary_key=True)
  tag = db.Column(db.String(128), primary_key=True)
  created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  username = db.Column(db.String(64), db.ForeignKey('account.username'))
  image = db.relationship("Image", back_populates="image_Text")

  def __init__(self, id, tag, username):
    self.id = id
    self.tag = tag
    self.username = username

class Image_TextQuery(object):
  @staticmethod
  def add_tag(image_id, tag_text, username):
    return True

  @staticmethod
  def remove_tag(image_id, tag_text = None):
    if tag_text == None:
      image_text = Image_Text.query.filter(Image_Text.id == image_id).delete()
      db.session.commit()
    else:
      image_text = Image_Text.query.filter(Image_Text.id == image_id, Image_Text.tag == tag_text).first()
      db.session.delete(image_text)
      db.session.commit()
    
    return True

  @staticmethod
  def get_tags_to_image(image_id):
    image_Texts = Image_Text.query.filter_by(id=image_id).all()
    list_of_tags = [image_Text.tag for image_Text in image_Texts]
    return list_of_tags

  @staticmethod
  def count_tags_from_user(username):
    tag_count = Image_Text.query.filter_by(username=username).count()
    return tag_count

class Filter(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(128))
  label = db.Column(db.String(128))
  value = db.Column(db.Integer)
  permission_required = db.Column(db.Boolean, default=True)
  account_filter_rel = db.relationship("Account_Filter", back_populates="filter_rel")

class FilterQuery(object):
  @staticmethod
  def get_all_filters():
    filters = Filter.query.order_by(Filter.id).all()
    return filters

  @staticmethod
  def get_all_filters_above_value(value):
    filters = Filter.query.filter(Filter.value >= value).order_by(Filter.id).all()
    
    res = []
    for f in filters:
      res.append([f.value, f.name, f.label])

    return res

  @staticmethod
  def get_permission_filters():
    filters = Filter.query.filter(Filter.permission_required == True).order_by(Filter.id).all()

    names = []
    values = []
    for f in filters:
      names.append(f.name)
      values.append(f.value)

    return (names, values)

  @staticmethod
  def get_filter_by_value(value):
    f = Filter.query.filter(Filter.value == value).first()
    return [f.value, f.name, f.label]

class Account_Filter(db.Model):
  user_id = db.Column(db.Integer, db.ForeignKey('account.id'), primary_key=True)
  filter_id = db.Column(db.Integer, db.ForeignKey('filter.id'), primary_key=True)
  account_rel = db.relationship("Account", back_populates="filter_rel")
  filter_rel = db.relationship("Filter", back_populates="account_filter_rel")

  def __init__(self, user, filter):
    self.user_id = user
    self.filter_id = filter

class Account_FilterQuery(object):
  @staticmethod
  def get_user_filters(account_id):
    filters = Account_Filter.query.filter(Account_Filter.user_id == account_id).all()

    res = []
    for f in filters:
      res.append([f.filter_rel.value, f.filter_rel.name, f.filter_rel.label])
    
    return res

  @staticmethod
  def add_user_filters(account_id, filter):
    acc_filter = Account_Filter(account_id, filter)
    db.session.add(acc_filter)
    db.session.commit()
    return None

  @staticmethod
  def remove_user_filters(account):
    user = Account.query.filter(Account.username == account).first()
    Account_Filter.query.filter(Account_Filter.user_id == user.id).delete()
    db.session.commit()
    return None