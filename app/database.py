from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class UserPassword(Base):
    __tablename__ = 'user_passwords'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

engine = create_engine('sqlite:///passwords.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def save_password(username, password):
    session = Session()
    user_password = UserPassword(username=username, password=password)
    session.add(user_password)
    session.commit()