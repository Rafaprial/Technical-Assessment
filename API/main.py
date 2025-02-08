from fastapi import FastAPI

app = FastAPI()

# First API endpoint
@app.get("/")
def read_root():
    return {"message": "Vulnerability API is running!"}
