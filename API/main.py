from fastapi import FastAPI, APIRouter
from routers import populate_router as populate
from database.database_setup import init_db

app = FastAPI()
router = APIRouter()
init_db()

# First API endpoint


@app.get("/")
def read_root():
    return {"message": "Vulnerability API is running!"}

# Router to populate the db the first time


app.include_router(populate.router)
