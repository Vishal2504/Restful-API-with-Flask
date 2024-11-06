# Restful-API-with-Flask

Flask Todo API

This is a simple Flask-based RESTful API for managing users and todos. The application uses JWT for authentication and SQLAlchemy for database management. It also supports file uploads with some basic error handling.
Features

    User Management: Create, retrieve, update (promote to admin), and delete users.
    Todo Management: Create, retrieve, update (mark as complete), and delete todos.
    File Upload: Upload files to a specific directory with checks for allowed file types.
    Authentication: Secure access using JWT (JSON Web Tokens).
    Error Handling: Custom error responses for different types of issues (e.g., bad requests, unauthorized access, etc.).

Requirements

    Python 3.x
    Flask
    Flask-SQLAlchemy
    Flask-Werkzeug
    PyJWT

You can install the required dependencies with the following:

pip install -r requirements.txt

Example requirements.txt

Flask==2.2.2
Flask-SQLAlchemy==3.0.0
Flask-Werkzeug==2.2.2
PyJWT==2.6.0

Setup

    Clone the repository:

git clone <repository_url>
cd <project_directory>

Set up the database (SQLite in this case) by running the following in the Python shell:

from app import db
db.create_all()

Run the Flask application:

    python app.py

    By default, the app runs on http://127.0.0.1:5000/.

API Endpoints
1. User Management

    Create a user

    POST /user
        Requires admin authentication.
        Expects JSON payload with name and password.

    Get all users

    GET /user
        Requires admin authentication.
        Returns a list of all users.

    Get a user by public ID

    GET /user/<public_id>
        Requires admin authentication.
        Returns user details by their public_id.

    Promote a user to admin

    PUT /user/<public_id>
        Requires admin authentication.
        Promotes the user with the specified public_id to admin.

    Delete a user

    DELETE /user/<public_id>
        Requires admin authentication.
        Deletes the user with the specified public_id.

2. Todo Management

    Get all todos for the logged-in user

    GET /todo
        Requires authentication.
        Returns a list of todos for the authenticated user.

    Get a specific todo

    GET /todo/<todo_id>
        Requires authentication.
        Returns a todo by its todo_id.

    Create a todo

    POST /todo
        Requires authentication.
        Expects JSON payload with text for the new todo.

    Complete a todo

    PUT /todo/<todo_id>
        Requires authentication.
        Marks the specified todo as completed.

    Delete a todo

    DELETE /todo/<todo_id>
        Requires authentication.
        Deletes the specified todo.

3. File Upload

    Upload a file

    POST /upload
        Requires authentication.
        Expects a file to be uploaded in the form data.
        Only supports files with extensions: txt, pdf, png, jpg, jpeg, gif.

4. Public Todos

    Get public todos

    GET /public/todos
        Publicly accessible.
        Returns a list of incomplete todos that are available for public view.

5. Login

    Login and get a JWT token

    POST /login
        Expects username and password via basic authentication.
        Returns a JWT token for authenticated users.

Error Handling

The API includes custom error handlers for:

    400: Bad Request
    401: Unauthorized (authentication errors)
    404: Not Found (resource not found)
    500: Internal Server Error
    413: Payload Too Large (when the uploaded file exceeds the allowed size)

Authentication

    The application uses JWT (JSON Web Tokens) for authentication.
    To access protected routes, you must include the JWT in the x-access-token header of your requests.


ENDPOINT

    i have created a one endpoint image folder in which i have all screenshot atteched.

File Upload

    Uploaded files are stored in the uploads folder.
    Allowed file types include txt, pdf, png, jpg, jpeg, and gif.
 
