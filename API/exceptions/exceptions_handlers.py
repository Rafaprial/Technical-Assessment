from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from utils.logger import logger

app = FastAPI()

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP error occurred: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

class VulnerabilityAlreadyExistsException(HTTPException):
    pass

@app.exception_handler(VulnerabilityAlreadyExistsException)
async def handle_vulnerability_already_exists_exception(request: Request, exc: VulnerabilityAlreadyExistsException):
    logger.error(f"Vulnerability already exists error: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

class VulnerabilityNotFoundException(HTTPException):
    pass

@app.exception_handler(VulnerabilityNotFoundException)
async def handle_vulnerability_not_found_exception(request: Request, exc: VulnerabilityNotFoundException):
    logger.error(f"Vulnerability not found error: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )
