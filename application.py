from flask import Flask,render_template, request, redirect, url_for, flash, jsonify
from flask import session as login_session
import random, string
import json as jso
from functools import wraps

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

from flask import make_response
import requests

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)

CLIENT_ID = jso.loads( open( 'client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

#login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash('Sorry but you need to log in first.')
            return redirect(url_for('homePage'))
    return wrap


@app.route('/')
def homePage():
    categories = session.query(Category).order_by(Category.name).all()
    items = session.query(Item).order_by(Item.id).all()

    login_session['state'] = state
    loggedIn = ""
    if 'username' in login_session:
        loggedIn = login_session['username']

    return render_template('main.html', categories = categories, items = items, STATE=state(), user = loggedIn)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(jso.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            jso.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = jso.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(jso.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            jso.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            jso.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(jso.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    #check if user exists, otherwise create new user
    user_id = getUserID(login_session['username'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    flash('Successfully logged in')
    return redirect(url_for('homePage'))


@app.route('/logout')
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            jso.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        loggedIn = ""

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            jso.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/category/<string:category_name>/')
def category(category_name):
    categories = session.query(Category).order_by(Category.name).all()
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).order_by(Item.name).filter_by(category_name = category.name).all()
    
    return render_template('category.html', categories = categories, category = category, items = items) 


@app.route('/category/<string:category_name>/<string:item_name>/')
def item(category_name, item_name):
    categories = session.query(Category).order_by(Category.name).all()
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Item).order_by(Item.name).filter_by(category_name = category.name, name = item_name).one()
    
    return render_template('item.html', categories = categories, category = category, item = item) 


@app.route('/newCategory', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCat = Category(name = request.form['name'], user_id = login_session['user_id'])
        session.add(newCat)
        session.commit()
        flash("New category created")
        return redirect(url_for('homePage'))

    categories = session.query(Category).order_by(Category.name).all()
    return render_template('newcategory.html', categories = categories)


@app.route('/category/<string:category_name>/newitem', methods=['GET', 'POST'])
@login_required
def newItem(category_name):
    #check user permissions
    cat = session.query(Category).filter_by(name = category_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to add items in this category.")
        return redirect(url_for('category', category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        newItem = Item(name = request.form['name'], category_name=category_name, user_id = login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("New item created")
        return redirect(url_for('category', category_name=category_name))

    return render_template('newitem.html', category_name=category_name)


@app.route('/catalog.json')
def json():
    #category = session.query(Category).filter_by(name = category_name).all()
    items = session.query(Item).order_by(Item.id).all()
    
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<string:category_name>/editcategory', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    #check user permissions
    cat = session.query(Category).filter_by(name = category_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to edit this category.")
        return redirect(url_for('category', category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        session.query(Category.name).filter(Category.name == category_name).update({Category.name: request.form['name']})
        session.commit()
        flash("Category edited.")
        return redirect(url_for('category', category_name=category_name))

    return render_template('editcategory.html', category_name=category_name)


@app.route('/category/<string:category_name>/deletecategory', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    #check user permissions
    cat = session.query(Category).filter_by(name = category_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to delete this category.")
        return redirect(url_for('category', category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        session.query(MenuItem.name).filter(MenuItem.id == menu_id).delete()
        session.query(Category.name).filter(Category.name == category_name).delete()
        session.commit()
        flash("Category deleted.")
        return redirect(url_for('homePage', ))

    return render_template('deletecategory.html', category_name=category_name)


def createUser(login_session):
    newUser = User(name = login_session['username'], 
                email = login_session['email'],
                picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(name = login_session['username']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


def getUserID(username):
    try:
        user = session.query(User).filter_by(name = username).one()
        return user.id
    except:
        return None


def state():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


if __name__ == '__main__':
    app.secret_key = 'fsdfkadhfakds687689768sfdasdfsdaf'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000) 
