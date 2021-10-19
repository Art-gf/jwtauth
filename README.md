# jwtauth
Authorization server with mongoDB

Contain 4 paths with using POST:
>/register
>
>/login
>
>/authorize
>
>/refresh

/register Registration new user, request JSON:
{
    "name": "Alice",
    "password": "12345"
}


/login Login user, request JSON:
{
    "name": "Alice",
    "password": "12345"
}
and response:
{
  "guid": "fdd..."
}

/authorize Authorize user, request JSON:
{
    "guid": "fdd..."
}
and response JWT tokens: 
{
  "access": "eyJ0...",
  "refresh": "eyJ..."
}

/refresh Refresh token, request JSON: 
{
  "access": "eyJ0...",
  "refresh": "eyJ..."
}
and response, if need refresh or not, or refresh token is expired

Config .json must be contained in dir with executable file
