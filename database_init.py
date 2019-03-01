from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
from Data_Setup import *

engine = create_engine('sqlite:///tractors.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Delete BykesCompanyName if exisitng.
session.query(TractorName).delete()
# Delete BykeName if exisitng.
session.query(ItemName).delete()
# Delete User if exisitng.
session.query(User).delete()

# Create sample users data
User1 = User(name="Gangasani Likitha",
                 email="likithagangasani@gmail.com",
                 picture='http://www.enchanting-costarica.com/wp-content/'
                 'uploads/2018/02/jcarvaja17-min.jpg')
session.add(User1)
session.commit()
print ("Successfully Add First User")
# Create sample byke companys
Tractor1 = TractorName(name="MAHINDRA",
                     user_id=1)
session.add(Tractor1)
session.commit()

Tractor2 = TractorName(name="TAFE",
                     user_id=1)
session.add(Tractor2)
session.commit

Tractor3 = TractorName(name="SWARAJ TRACTORS",
                     user_id=1)
session.add(Tractor3)
session.commit()

Tractor4 = TractorName(name="SONALIKA TRACTORS",
                     user_id=1)
session.add(Tractor4)
session.commit()

Tractor5 = TractorName(name="NEW HOLLAND",
                     user_id=1)
session.add(Tractor5)
session.commit()

Tractor6 = TractorName(name="JOHN DEERE",
                     user_id=1)
session.add(Tractor6)
session.commit()

# Populare a bykes with models for testing
# Using different users for bykes names year also
Item1 = ItemName(name="Mahindra Yuvaraj",
                       engine="2300 cc",
                       price="6.30 Lakh",
                       liftcapacity="778 kg",
                       date =datetime.datetime.now(),
                       tractornameid=1,
                       user_id=1)
session.add(Item1)
session.commit()

Item2 = ItemName(name="Orchard Plus",
                       engine="1670 cc",
                       price="10.0 Lakhs",
                       liftcapacity="1100 kg",
                       date=datetime.datetime.now(),
                       tractornameid=2,
                       user_id=1)
session.add(Item2)
session.commit()

Item3 = ItemName(name="Swaraj 960FE",
                       engine="2434 cc",
                       price="7.40 Lakh",
                       liftcapacity="1500 kg",
                       date=datetime.datetime.now(),
                       tractornameid=3,
                       user_id=1)
session.add(Item3)
session.commit()

Item4 = ItemName(name="DI 60",
                       engine="2000 cc",
                       price="7.51 Lakh",
                       liftcapacity="2000 kg",
                       date=datetime.datetime.now(),
                       tractornameid=4,
                       user_id=1)
session.add(Item4)
session.commit()

Item5 = ItemName(name="4710 with Conopy 2WD",
                        engine="2931 cc",
                       price="8.85 Lakh",
                       liftcapacity="4400 kg",
                       date=datetime.datetime.now(),
                       tractornameid=5,
                       user_id=1)
session.add(Item5)
session.commit()

Item6 = ItemName(name="5036 DI 2WD",
                        engine="2100 cc",
                       price="6 Lakh",
                       liftcapacity="1300 kg",
                       date=datetime.datetime.now(),
                       tractornameid=6,
                       user_id=1)
session.add(Item6)
session.commit()

print("Your Sample Items database has been inserted!")
