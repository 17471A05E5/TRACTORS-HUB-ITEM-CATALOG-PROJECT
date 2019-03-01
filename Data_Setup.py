import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    picture = Column(String(300))


class TractorName(Base):
    __tablename__ = 'tractorname'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="tractorname")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            'name': self.name,
            'id': self.id
        }


class ItemName(Base):
    __tablename__ = 'itemname'
    id = Column(Integer, primary_key=True)
    name = Column(String(350), nullable=False)
    engine = Column(String(150))
    price = Column(String(150))
    liftcapacity = Column(String(150))
    date = Column(DateTime, nullable=False)
    tractornameid = Column(Integer, ForeignKey('tractorname.id'))
    tractorname = relationship(
        TractorName, backref=backref('itemname', cascade='all, delete'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="itemname")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            'name': self. name,
            'engine': self. engine,
            'price': self. price,
            'liftcapacity': self. liftcapacity,
            'date': self. date,
            'id': self. id
        }

engin = create_engine('sqlite:///tractors.db')
Base.metadata.create_all(engin)
