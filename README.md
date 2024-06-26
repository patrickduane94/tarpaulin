# Tarpaulin Flask App

## Overview
Tarpaulin is a Flask web application which allows user to manage courses, similar to Canvas. Users create an account with a role as either an admin, instructor, or student. The API endpoints and actions that a user has access to is determined by their role.

## Prerequisites
- Python 3.x
- Flask
- Auth0 account
- GCP Account with Datastore and Cloud Storage

## Setup

### Step 1: Clone the Repository
Clone the repository to your local machine:
```bash
git clone https://github.com/yourusername/tarpaulin.git
```

### Step 2: Install Dependencies
Install the required Python packages:
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
In the `main.py` file, replace the following variables with your specific configuration:

- `PHOTO_BUCKET`: The name of your AWS S3 bucket where photos are stored.
- `CLIENT_ID`: Your Auth0 Client ID.
- `CLIENT_SECRET`: Your Auth0 Client Secret.
- `DOMAIN`: Your Auth0 domain.
- `AUTH0_USERS_URL`: The Auth0 users URL.

```python
PHOTO_BUCKET = 'your-photo-bucket'
CLIENT_ID = 'your-client-id'
CLIENT_SECRET = 'your-client-secret'
DOMAIN = 'your-auth0-domain'
AUTH0_USERS_URL = 'https://your-auth0-domain/api/v2/users'
```

### Step 4: Run the Application
To start the Flask application, execute the following command:
```bash
flask run
```
By default, the application will run on `http://127.0.0.1:8080/`.
