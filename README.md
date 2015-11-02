Catalog

Catalog is a flask application for storing various items in an organized way. 
Logged users can create, edit and delete their categories and items.

## Set Up Environment
Explain how to install, start and connect to the virtual machine (vagrant)

## Requirements
Python (2.7) -> https://www.python.org/downloads/
Flask (0.9)
httplib2 (0.9.1)
Jinja2 (2.7.2)
oauth2client (1.5.1)
requests (2.2.1)
simplejson (3.8.0)
SQLAlchemy (0.8.4)
Werkzeug (0.8.3)

## Installation and run
1. Install required modules by typing in a terminal 'pip install module_name'
2. Download the application by clonning this repo 'git clone https://github.com/pmarki/catalog.git'
3. Run python application.py in the application folder
4. Type 'localhost:5000' in your browser's address bar.

## Usage
Log in by google or amazon. Then you are able to add categories and items to a category. 
You can also store images and links to an item as well as rate them.
Unlogged user is able to browse through catalog but can not change anything.

Url options:
/catalog.json - returns a json object with all categories and items
/recent.atom - return last 10 items in atom format
