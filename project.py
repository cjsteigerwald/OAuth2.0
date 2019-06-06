#!/usr/bin/env python
from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

#New imports for OAuth
from flask import session as login_session
import random, string

# JSON formatted style stores client ID, client secret and other OAuth 2.0 paramters
from oauth2client.client import flow_from_clientsecrets
# If run into an error trying to exchange an authorization code for an access token
# FlowExchangeError catches the error
from oauth2client.client import FlowExchangeError
# A comprehensive HTTP client library in Python to a serialized respresentation,
# know as JSON
import httplib2
# Provides an API for converting in memory Python objects 
import json
# Converts the response value from a function into a real response object that we
# can send off to the client
from flask import make_response
# An Apcache 2.0 licensed HTTP library written in Python
import requests
# Refreneces the client secrets file
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create a state toekn to prevent request fogery
# Store it in the sesion for later validation
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits))   
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# Route and funtion that accepts post requests
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # confirm that the token that the client sends to the server matches
    # the token that the server sent to the client
    # If invalid credentials send message to user
    if request.args.get('state') != login_session['state']:
      response = make_response(json.dumps('Invalid state'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response
    # Valid token, collect one time code from my server with the request.data function
    # gives one time code
    code = request.data
    # Try and exchange one time code to exchange for a credentials object, which
    # will contain the access token for my server
    try:
      print("In try")
      # Upgrade the authorization code into a credentials object
      # Create an OAuth flow object and adds my client's secret key information
      # to it
      oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
      # Specify with post message that this is the one to flow my server will 
      # be sending off
      oauth_flow.redirect_uri = 'postmessage'
      # Initiate the exchange with the step two exchange function, passing in my 
      # one-time code as input
      # Exchanges an authorization code for a credentials object
      print ("Above credentials")
      credentials = oauth_flow.step2_exchange(code)
      print("Credentials: \n%s" % credentials)
    # If an error happens, throw flow exchange error and send response as JSON object
    except FlowExchangeError:
      print("In exception")
      response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response
    print ("Outside try")
    # Check that the access token is valid
    access_token = credentials.access_token
    # Append token to below url, so Google API server can verify that this is
    # a valid token for use
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Create a JSON GET request containing the url and access token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET') [1])
    # If there was an error in the access token info, abort
    if result.get('error') is not None:
      print ("In result.get error")
      response = make_response(json.dumps(result.get('error')), 500)
      response.headers['Content-Type'] = 'application/json'
    # Verify that the access token is used for the intended user.
    # Grab the id of the token in my credentials object and compare it to the
    # ID returned by the Google API server
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
      respone = make_response(
        json.dumps("Token's user ID doesn't match given user ID."), 401)
      respone.headers['Content-Type'] = 'application/json'
      return response

    # Check if user is already logged into server
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
      # Returns successful 200 without resetting all of the login session 
      # variables again
      response = make_response(json.dumps('Current user is already conneted'), 200)
      respone.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info from Google Plus API, by sending messagae to the Google API
    # server with my access token. Requesting user info allowed by my token and
    # scope and store in an object called data
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)

    data = json.loads(answer.text)

    # Store results from Google API: 
    # https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
  
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session.
# Disconect user from Google account, loggin them out of web app
@app.route("/gdisconnect")
def gdisconnect():
  # Only disconnect a connected user.
  access_token = login_session.get('access_token')
  # If credentials is empty no one is connected
  if access_token is None:
      print ('Access Token is None')
      response = make_response(json.dumps('Current user not connected.'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response

  # Pass access token to Google's url for revoking tokens
  print('User name is: ')
  print (login_session['username'])
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]

  # If response from Google is good, delete user data
  if result['status'] == '200':
    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    # Create response that user was successfully logged out of app
    response = make_response(json.dumps('Successfully disconnected'), 200)
    response.headers['Connet-Type'] = 'application/json'
    return response
  # Error is logging out user
  else:
    # For any reason, the given token was invalid
    response = make_response(json.dumps('Failed to revoke token for given user'),
      400)
    response.headers['Connet-Type'] = 'application/json'
    return response


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return render_template('menu.html', items = items, restaurant = restaurant)
     


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id)
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):

    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one() 
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)




if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
