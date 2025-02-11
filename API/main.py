from fastapi import FastAPI, APIRouter
from routers import populate_router as populate
from database.database_setup import init_db
from routers.vulnerabilities import router as vulnerabilities_router
from decorators.limiter import limiter
from slowapi import _rate_limit_exceeded_handler

from utils.logger import logger

app = FastAPI()
router = APIRouter()
init_db()


app.state.limiter = limiter

app.add_exception_handler(429, _rate_limit_exceeded_handler)

@app.on_event("startup")
async def startup():
    logger.debug("API started")
    pass

#vulnerabilities router
app.include_router(vulnerabilities_router)


@app.get("/")
def read_root():
    return {"message": "Vulnerability API is running!"}

# Router to populate the db the first time
app.include_router(populate.router)
