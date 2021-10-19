# FlaskBackEnd21October
Take home Flask assignment

Assumptions: each account can have only one role but 0 or many permissions. 

How to run:


    1. create a python virtual environment with python 3.9.7
    2. pip install -r requirements.txt
    3. python app.py
    4. the default URL is: 127.0.0.1:5000/

The backend starts with two predefined users:
```json
{
    "1": {
        "permissions": "company_list",
        "role": "admin",
        "username": "jj"
    },
    "2": {
        "permissions": "company_list",
        "role": "user",
        "username": "uu"
    }
}
```
both with password = 'SomeSecretPassword'. You can pass the username and password to endpoint "/api/token" to get a authentication token for the specific user. You can put the token in the user field and leave password field blank to represent the user for the next 800 seconds.

A simple breakdown of the api endpoints:
```json
{
    "/api/token": {
        "methods": ["GET", "POST"],
        "authentication": "login",
        "description": "exchange username-password combination with a login token",
        "response": {"token": "token"}
    },
    "/api/manageUsers/listUsers": {
        "methods": ["GET"],
        "authentication": "admin",
        "description": "list all user in the database",
        "response": {
            "user.id": {
                "username": "user.username",
                "role": "user.role",
                "permissions": "user.permissions"
            }
        }
    },
    "/api/manageUsers/createUser": {
        "methods": ["POST"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "username": "username",
                "role": "user",
                "password": "password",
                "permissions": ["company_info","company_list"]
            }
        },
        "description": "Create a user",
        "response": {
            "Success": {
                "id": "u.id", "username": "u.username", "role": "u.role", "permissions": "u.permissions"
            }
        }
    },
    "/api/manageUsers/updateUser": {
        "methods": ["POST"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "id/username": "choose at least one",
                "password": "optional",
                "role": "optional",
                "permissions": ["optional", "company_list"]
            }
        },
        "description": "update user information",
        "response": {
            "Success": {
                "id": "u.id", "username": "u.username", "role": "u.role", "permissions": "u.permissions"
            }
        }
    },
    "/api/manageUsers/deleteUser": {
        "methods": ["DELETE"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "id/username": "choose at least one"
            }
        },
        "description": "Delete a user by id or username",
        "response": {
            "Success": "successfully deleted user with id: {u.id} and username: {u.username}"
        }
    },
    "/api/CompanyLists/create": {
        "methods": ["POST"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "company_list": [1,2,3,4,5]
            }
        },
        "description": "Create a company list",
        "response": {
            "Success": 
                {
                    "id": "cl.id", "CompanyList": [1,2,3,4,5]
                }
        }
    },
    "/api/CompanyLists/list": {
        "methods": ["GET"],
        "authentication": ["admin", "user"],
        "description": "List all company lists",
        "response": {
            "cl.id": {
                "company_list": [1,2,3,4,5]
            }
        }
    },
    "/api/CompanyLists/delete": {
        "methods": ["DELETE"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "id": "company_list.id"
            }
        },
        "description": "Delete a company list by id",
        "response": {
            "Success": "successfully deleted company list with id: {cl.id} and content: {cl.company_list}"
        }
    },
    "/api/userCompanyListAssociation/create": {
        "methods": ["POST"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "userId": "uid",
                "companyListId": "clid"
            }
        },
        "description": "Associate user with company list on a many-to-many relationship",
        "response": {
            "Success": "Added association for user with id: {u.id} and username: {u.username} with company list: {cl.company_list}"
        }
    },
    "/api/userCompanyListAssociation/read/<uid>": {
        "methods": ["GET"],
        "authentication": "admin",
        "input": {
            "path parameter": {
                "uid": "userId"
            }
        },
        "description": "Read all user-CompanyList associations of a certain user",
        "response": {
            "cl.id": "cl.company_list"
        }
    },
    "/api/userCompanyListAssociation/delete": {
        "methods": ["DELETE"],
        "authentication": "admin",
        "input": {
            "application/json": {
                "userId": "uid",
                "companyListId": "clid"
            }
        },
        "description": "Delete a company-CompanyList association",
        "response": {
            "Success": "removed company list with id: {cl.id} and list: {cl.company_list}, from user with id: {u.id} and username: {u.username}"
        }
    },
    "/api/viewCompany/<company_id>": {
        "methods": ["GET"],
        "authentication": "user",
        "input": {
            "path parameter": {
                "company_id": "company_id"
            }
        },
        "description": "View the information about the company, simplified by doing sha256",
        "response": {"Company info": "sha256(str(company_id).encode('utf-8')).hexdigest()"}
    }
}
```