#Setup SQLAlchemy
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    name = Column( String(80), nullable = False )
    email = Column( String(80), nullable = True )
    picture = Column( String(80), nullable = True )
    id = Column( Integer, primary_key = True )

class Category(Base):
    __tablename__ = 'categories'
    
    id = Column( Integer, primary_key = True )
    name = Column( String(80), nullable = False, unique=True )
    description = Column( String(150), nullable = True )
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)
    
    @property
    def serialize(self):
        return {
            'name' : self.name,
            'description' : self.description,
            'id' : self.id
       }


class Item(Base):
    __tablename__ = 'items'
    
    name = Column( String(80), nullable = False )
    id = Column( Integer, primary_key = True)
    description = Column( String(450) )
    category_name = Column(String, ForeignKey('categories.name'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)
    
    @property
    def serialize(self):
        return {
            'name' : self.name,
            'description': self.description,
            'id': self.id,
            'category_name': self.category_name
        }



engine = create_engine( 'sqlite:///catalog.db')

Base.metadata.create_all(engine)
