from flask import Flask,render_template, request, redirect, url_for, flash, jsonify
from flask import session as login_session
import random, string
import json as jso
from functools import wraps

from urlparse import urljoin
from werkzeug.contrib.atom import AtomFeed
import datetime

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

from flask import make_response, abort, current_app
import requests

from sqlalchemy import create_engine, func
from sqlalchemy.sql import label
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
def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if 'username' in login_session:
            return fn(*args, **kwargs)
        else:
            flash('Sorry but you need to log in first.')
            return redirect(url_for('homePage'))
    return wrap


#ssl for amazon login
def ssl_required(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        if current_app.config.get("SSL"):
            if request.is_secure:
                return fn(*args, **kwargs)
            else:
                return redirect(request.url.replace("http://", "https://"))    
        return fn(*args, **kwargs)        
    return decorated_view

@app.route('/')
def homePage():
    items = session.query(Item).order_by(Item.id.desc()).limit(10)
    return render_template('main.html', items = items, categories = categories(),  STATE=state(), user = loggedIn())


@app.route('/aconnect')
@ssl_required
def aconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(jso.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
     
    access_token = request.args.get('access_token')
    # verify that the access token belongs to us
    url = "https://api.amazon.com/auth/o2/tokeninfo?access_token=" + access_token
    h = httplib2.Http()
    result = jso.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        flash('Unable to log in. Incorrect token provided.')
        return redirect(url_for('homePage'))

    if result['aud'] != 'amzn1.application-oa2-client.fad2e989b87d4c6c9b6fef52d18e04d0' :
        # the access token does not belong to us
        flash('Unable to log in. Incorrect token provided.')
        return redirect(url_for('homePage'))
     
    # exchange the access token for user profile
    url = "https://api.amazon.com/user/profile"
    headers={'Authorization':'bearer %s'%(access_token)}
    h = httplib2.Http()
    result = jso.loads(h.request(url, 'GET', headers=headers)[1])
    if result.get('error') is not None:
        flash( result["error"] )
        return redirect(url_for('homePage'))

    login_session['username'] = result['name']
    login_session['email'] = result['email']
    login_session['access_token'] = access_token
    login_session['login_provider'] = "amazon"

    #check if user exists, otherwise create new user
    user_id = getUserID(login_session['username'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    flash('Logged in.')
    return redirect(url_for('homePage'))


def adisconnect():
    del login_session['access_token']
    del login_session['username']
    del login_session['email']

    flash('Successfully logged out.')
    return redirect(url_for('homePage'))


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
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['login_provider'] = "google"

    #check if user exists, otherwise create new user
    user_id = getUserID(login_session['username'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return login_session['username']


@app.route('/logout')
def logout():
    if login_session['login_provider'] == "amazon":
        return adisconnect()

    if login_session['login_provider'] == "google":
        return gdisconnect()

def gdisconnect():
    # Only disconnect a connected user.
    if 'access_token' not in login_session:
        flash('Current user not connected.')
        return redirect(url_for('homePage'))

    #access_token = credentials.access_token
    access_token = login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        flash('Successfully logged out.')
        return redirect(url_for('homePage'))
    else:
        # For whatever reason, the given token was invalid.
        #response = make_response(
         #   jso.dumps('Failed to revoke token for given user.', 400))
        #response.headers['Content-Type'] = 'application/json'
        #return response
        flash('Failed to revoke token for given user.')
        return redirect(url_for('homePage'))


@app.route('/category/<string:category_name>/')
def category(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).order_by(Item.name).filter_by(category_name = category.name).all()
    
    return render_template('category.html', category = category, items = items, categories = categories(),  STATE=state(), user = loggedIn()) 


@app.route('/category/<string:category_name>/<string:item_name>/')
def item(category_name, item_name):
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Item).order_by(Item.name).filter_by(category_name = category.name, name = item_name).one()
    
    return render_template('item.html', category = category, item = item, categories = categories(),  STATE=state(), user = loggedIn()) 


@app.route('/newCategory', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        try:

            newCat = Category(name = request.form['name'], user_id = login_session['user_id'], description = request.form['description'])
            session.add(newCat)
            session.commit()
            flash("New category created.")
            return redirect(url_for('homePage'))
        except:
            session.rollback()
            flash("Category '" + request.form['name'] + "' already exists")


    return render_template('newcategory.html', categories = categories(),  STATE=state(), user = loggedIn())


@app.route('/category/<string:category_name>/editcategory', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    #check if user is allowed to edit the category
    cat = session.query(Category).filter_by(name = category_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to edit this category.")
        return redirect(url_for('category', category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        session.query(Category.name).filter_by(name = category_name).update({Category.name: request.form['name']})
        session.query(Category.name).filter_by(name = category_name).update({Category.description: request.form['description']})
        session.query(Item.category_name).filter_by(category_name = category_name).update({Item.category_name: request.form['name']})
        session.commit()
        flash("Category edited.")
        return redirect(url_for('category', category_name=request.form['name']))

    #show edit category page
    category = session.query(Category).filter_by(name = category_name).one()
    return render_template('editcategory.html', category=category, categories = categories(),  STATE=state(), user = loggedIn())


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
        session.query(Item.category_name).filter_by(category_name = category_name).delete()
        session.query(Category).filter(Category.name == category_name).delete()
        session.commit()
        flash("Category deleted.")
        return redirect(url_for('homePage'))

    #show delete category page
    return render_template('deletecategory.html', category_name=category_name, categories = categories(),  STATE=state(), user = loggedIn())


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
        newItem = Item(name = request.form['name'], category_name=category_name, user_id = login_session['user_id'], description = request.form['description'], rate = request.form['rate'], url = request.form['url'])
        session.add(newItem)
        session.commit()
        flash("New item created")
        return redirect(url_for('category', category_name=category_name))

    return render_template('newitem.html', category_name=category_name, categories = categories(),  STATE=state(), user = loggedIn())


@app.route('/category/<string:category_name>/<string:item_name>/edititem', methods=['GET', 'POST'])
@login_required
def editItem(item_name, category_name):
    #check if user is allowed to edit the item
    cat = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to edit this item.")
        return redirect(url_for('item', item_name=item_name, category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        session.query(Item.name).filter_by(category_name = category_name, name = item_name).update({Item.name: request.form['name']})
        session.query(Item.description).filter_by(category_name = category_name, name = item_name).update({Item.description: request.form['description']})
        session.query(Item.description).filter_by(category_name = category_name, name = item_name).update({Item.url: request.form['url']})
        session.query(Item.description).filter_by(category_name = category_name, name = item_name).update({Item.rate: request.form['rate']})
        session.query(Item.description).filter_by(category_name = category_name, name = item_name).update({Item.category_name: request.form['category']})
        session.commit()
        flash("Item edited.")
        return redirect(url_for('category', category_name=category_name))

    #show edit item page
    item = session.query(Item).filter_by(name = item_name, category_name = category_name).one()
    return render_template('edititem.html', item=item, categories = categories(),  STATE=state(), user = loggedIn())


@app.route('/category/<string:category_name>/<string:item_name>/deleteitem', methods=['GET', 'POST'])
@login_required
def deleteItem(item_name, category_name):
    #check if user is allowed to edit the item
    cat = session.query(Category).filter_by(name = category_name).one()
    if cat.user_id  != login_session['user_id']:
        flash("You are not allowed to delete this item.")
        return redirect(url_for('item', item_name=item_name, category_name=category_name))

    #proceed with request
    if request.method == 'POST':
        #session.query(Item.category_name).filter_by(category_name = category_name).update({Item.category_name: request.form['new_category']})
        session.query(Item).filter_by(category_name = category_name, name = item_name).delete()
        session.commit()
        flash("Item deleted.")
        return redirect(url_for('category', category_name=category_name))

    #show delete item page
    item = session.query(Item).filter_by(name = item_name, category_name = category_name).one()
    return render_template('deleteitem.html', item=item, categories = categories(),  STATE=state(), user = loggedIn())


@app.route('/catalog.json')
def json():
    categories = session.query(Category).order_by(Category.name).all()
    catalog = {}

    for cat in categories:
        category = {}
        category["description"] = cat.description
        items = []
        user_alias = aliased(User)
        for it in session.query(Item, User).join(User, Item.user_id==User.id)\
            .filter(Item.category_name == cat.name)\
            .order_by(Item.name).all():

            item = {}
            item["owner"] = it[1].name #user name
            item["id"] = it[0].id
            item["name"] = it[0].name
            item["description"] = it[0].description
            items.append(item)

        category["items"] = items
        catalog[cat.name] = category

    return jsonify(catalog)


@app.route('/recent.atom')
def recent_feed():
    feed = AtomFeed('Recent Items',
                    feed_url=request.url, url=request.url_root)
    items = session.query(Item).order_by(Item.id.desc()).limit(10).all()

    for item in items:
        feed.add(item.name, unicode(item.category_name),
                 content_type='html',
                 url=url_for("item", item_name = item.name, category_name = item.category_name),
                 updated=datetime.datetime.now() #a cheat with time, I know ;)
                 )
    return feed.get_response()


## Helper functions ##    


#Create user form login_session and return user.id
def createUser(login_session):
    newUser = User(name = login_session['username'], 
                email = login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(name = login_session['username']).first()
    return user.id


#Return user object with given user_id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


#return user.id if user with given username exists, otherwise return None
def getUserID(username):
    try:
        user = session.query(User).filter_by(name = username).one()
        return user.id
    except:
        return None


#return state key for authentication
def state():
    if 'state' not in login_session:
        login_session['state'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    return login_session['state']


#Return all categories 
def categories():
    categories = session.query(Category, func.count(Item.id)).outerjoin(Item).group_by(Category)
    return categories


#Return username or empty string if nobody is logged in
def loggedIn():
    user = ""
    if 'username' in login_session:
        user = login_session['username']
    return user



if __name__ == '__main__':
    app.secret_key = 'fsdfsdg56546fkadhfautfd867asdfsdaf'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000) 
