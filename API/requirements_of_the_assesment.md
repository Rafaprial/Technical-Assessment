# Pending
 - Loggers
 - Check all the different security mesures
 - Apply corresponding API KEY to each router
 - Test
  . Unit test & regresion
 - Study DDOS protection






 # Technical Assessment - C# & Python
 
 - In this technical test, you are expected to develop, in the way you feel most comfortable, two interconnected solutions. One of them should be in Python and the other in C#. 
 - Both solutions must be containerized using Docker to ensure they can be used across different operating systems. 
 - The code should be made public in a GIT repository, with appropriate documentation so that any user can freely use it.
 - Additionally, optimize the performance of your solutions to handle large datasets efficiently.
 - The evaluation criteria will include code quality, documentation, testing, security, and performance.
 
 ## Python - API REST
 
 Create a Python API that handles the following CRUD operations. You can use your preferred API framework to fulfill the task.
 
 > Notes:  
 > `Title`: String of 30 characters max.  
 > `CVE`: String that matches the `CVE-\d{4}-\d{4,7}` regex. **It is unique.**  
 > `Criticality`: Integer from 0 to 10, both inclusive.  
 > `Description`: String of 100 characters max.
 
 ### /GET
 - `/vulnerability/{cve}`
     - Returns the vulnerability by CVE.
     - Potential status codes: `400, 404, 500`.
 - `/vulnerability`
     - Retrieves all vulnerabilities if any filter is applied.
     - It must allow filtering by the following parameters:
         - `Title`: contains.
         - `Max/Min Criticity`: values in between.
     - Potential status codes: `400, 404, 500`.
 
 ### /POST
 - `/vulnerability`
     - Creates a new vulnerability object.
     - The values of the new object must be included in the body.
     - Potential status codes: `400, 404, 500`.
 
 ### /DELETE
 - `/vulnerability/{cve}`
     - Removes the specific vulnerability.
     - Returns the removed vulnerability.
     - Potential status codes: `400, 404, 500`.
 
 
 ## C# - Command Line Interface
 
 A Command Line Interface (CLI) is required to read a JSON file with several vulnerabilities and upload them to the previously created API.
 
 Make sure to log and continue to the next vulnerability if an error raises while reading and parsing any vulnerability from the JSON file.
 
 The JSON File schema is provided in the [Data Model](#data-model).
 
 ### CLI Usage:
 ```bash
 $ vulnerability-cli [OPTIONS] [ARGS]...
 $ vulnerability-cli --file {JSON_FILE} --url {API_URL}
 ```
 
 ## Data Model
 This is the Schema for the creation of the JSON File.
 ```json
 {
     "$defs": {
         "Vulnerability": {
             "properties": {
                 "title": {
                     "title": "Title",
                     "type": "string"
                 },
                 "description": {
                     "anyOf": [
                         {
                             "type": "string"
                         },
                         {
                             "type": "null"
                         }
                     ],
                     "title": "Description"
                 },
                 "cve": {
                     "anyOf": [
                         {
                             "type": "string"
                         },
                         {
                             "type": "null"
                         }
                     ],
                     "title": "Cve"
                 },
                 "criticality": {
                     "title": "Criticality",
                     "type": "integer"
                 }
             },
             "required": [
                 "title",
                 "description",
                 "cve",
                 "criticality"
             ],
             "title": "Vulnerability",
             "type": "object"
         }
     },
     "properties": {
         "vulnerabilities": {
             "items": {
                 "$ref": "#/$defs/Vulnerability"
             },
             "title": "Vulnerabilities",
             "type": "array"
         }
     },
     "required": [
         "vulnerabilities"
     ],
     "title": "Data",
     "type": "object"
 }
 ```
 