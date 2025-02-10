# Technical-Assessment
Technical assesssment for Swiss Re

# FastAPI Vulnerability Management API

This is a FastAPI-based API designed to manage vulnerabilities through CRUD operations. It supports handling large datasets, integrates security mechanisms like API key authentication, and protects against common attacks such as SQL injection and DDoS.

## Features
- **CRUD Operations** for managing vulnerabilities.
- **API Key Authentication** for secure access.
- **Pagination** to handle large datasets efficiently.
- **SQL Injection Protection** using SQLAlchemy.
- **Rate Limiting** to protect against DDoS attacks.
- **Connection Pooling** for efficient database connections.

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
 
 ### /DELETE 
 - `/vulnerability/{cve}` -> Admin API KEY required
     - Removes the specific vulnerability.
     - Returns the removed vulnerability.
     - Potential status codes: `400, 404, 500`.
 

# USAGE
To run the app .env file needs to be created and API keys assigned for example:

ADMIN_API_KEY=admin_secret_api_key
USER_API_KEY=user_secret_api_key

To run locally the API while being in /API/
uvicorn main:app --reload
