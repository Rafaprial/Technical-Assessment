from databases import Database
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./database.db"
# Connection string to the database (File database.db in the home directory)

database = Database(DATABASE_URL)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Function to create database tables


def init_db():
    Base.metadata.create_all(bind=engine)
