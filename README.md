# FlaskBackEnd21October
Take home Flask assignment

Assumptions: each account can have only one role but 0 or many permissions. 

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