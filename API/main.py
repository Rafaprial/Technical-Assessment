from fastapi import FastAPI, APIRouter
from routers import populate_router as populate
from database.database_setup import init_db
from routers.vulnerabilities import router as vulnerabilities_router

app = FastAPI()
router = APIRouter()
init_db()

@app.on_event("startup")
async def startup():
    pass

#vulnerabilities router
app.include_router(vulnerabilities_router)


@app.get("/")
def read_root():
    return {"message": "Vulnerability API is running!"}

# Router to populate the db the first time
app.include_router(populate.router)
