# Technical-Assessment
Technical assesssment for Swiss Re

# FastAPI Vulnerability Management API

This is a FastAPI-based API designed to manage vulnerabilities through CRUD operations. It supports handling large datasets, integrates security mechanisms like API key authentication, and protects against common attacks such as SQL injection and DDoS.

## Added Features
- **CRUD Operations** for managing vulnerabilities.
- **API Key Authentication** for secure access.
- **Pagination** to handle large datasets efficiently.
- **SQL Injection Protection** using SQLAlchemy.
- **Rate Limiting** to protect against DDoS attacks.
- **Connection Pooling** for efficient database connections.
- **Logger** for logging proccesses and errors during execution
- **Populate** for having easy access to DB
- **Features in model** to have logical delete, creation and update time


## Endpoints

 ## Python - API REST
 
 Create a Python API that handles the following CRUD operations. You can use your preferred API framework to fulfill the task.
 
 > Notes:  
 > `Title`: String of 30 characters max.  
 > `CVE`: String that matches the `CVE-\d{4}-\d{4,7}` regex. **It is unique.**  
 > `Criticality`: Integer from 0 to 10, both inclusive.  
 > `Description`: String of 100 characters max.
 
 ### /GET
 - `/vulnerability/{cve}` -> User/Admin API KEY required
     - Returns the vulnerability by CVE.
     - Potential status codes: `400, 404, 500`.
 - `/vulnerability` -> User/Admin API KEY required
    - Retrieves all vulnerabilities if any filter is applied.
    - Params:
        - `limit` -> How much data entries retreives. MAX 100
        - `skip` -> Pagination.
        Example:
            ?limit=1&skip=19 -> it will retreive the entry number 20 from the DB
     
     - It must allow filtering by the following parameters:
         - `Title`: contains.
         - `Max/Min Criticity`: values in between.
         - `Params`
            - min_criticity : int
            - max_criticity : int
            - title : string
     - Potential status codes: `400, 404, 500`.
 
 ### /POST
 - `/vulnerability` -> Admin API KEY required
     - Creates a new vulnerability object.
     - The values of the new object must be included in the body.
     - Potential status codes: `400, 404, 500`.
        - Creation of multiple vulnerabilities in a single request
        - Handle large datasets
*Example of a body*
[
  {
    "cve": "CVE-2023-32353",
    "title": "Vulnerability 1",
    "criticality": 5,
    "description": "Description for vulnerability 1"
  },
  {
    ...
  }
]

 
 ### /DELETE 
 - `/vulnerability/{cve}` -> Admin API KEY required
 - This method has a logical delete so its easier to trace back errors and avoid data losing
     - Removes the specific vulnerability.
     - Returns the removed vulnerability.
     - Potential status codes: `400, 404, 500`.
 
  
 ### /POST 
 - `/populate` -> Admin API KEY required
 - This method populates the db for testing porpouses
     - Potential status codes: `400, 404, 500`.

# USAGE
**Run locally without docker**  
**Requirements**  
Python 3.13

*Inside API folder the .env file should be created and secrets be placed*  
Example of .env  
ADMIN_API_KEY=admin_secret_api_key    
USER_API_KEY=user_secret_api_key  
  
*From inside API folder the requirements should be installed*  
*Nice practice is to create a enviroment to hold all the required dependencies*  
python -m venv env  
  
*Once created to active it is through*  
source ~/env/Scripts/activate  
  
*Then to install requirements*  
pip install -r requirements.txt  
  
*To run locally the API while being in /API/*  
uvicorn main:app --reload  
  
**To run in Docker**  
*Requirements*  
Docker Desktop  
  
*Inside API folder the .env file should be created and secrets be placed. To be used also it needs to be removed from .gitignore*  
Example of .env  
ADMIN_API_KEY=admin_secret_api_key  
USER_API_KEY=user_secret_api_key  
  
  
**Commands**  
docker build -t vulnerabilities_api .  
docker run --env-file .env -p 8000:8000 vulnerabilities_api  