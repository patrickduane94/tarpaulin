from flask import Flask, request, send_file, jsonify, render_template, redirect, url_for, session, flash, make_response
from google.cloud import storage, datastore
import io
import requests
import json
from functools import wraps
from datetime import datetime, timezone
import http.client

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

PHOTO_BUCKET = ''

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''


ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    if ex.status_code == 401:
        return redirect(url_for('login_user'))
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def is_token_expired(token):
    try:
        # Decode the token without verifying the signature to get the payload
        payload = jwt.get_unverified_claims(token)
        exp = payload.get('exp')
        if exp:
            # Convert expiration time to datetime
            exp_datetime = datetime.fromtimestamp(exp, timezone.utc)
            return exp_datetime < datetime.now(timezone.utc)
        return True  # If there's no expiration claim, consider it expired
    except jwt.JWTError:
        return True  # If there's any error in decoding, consider it expired


def get_auth0_user_info(user_id):
    #replace ... with auth0 users url
    url = f'.../{user_id}'
    token = session.get('api_token')
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(
            f"Failed to retrieve user info for {user_id}, status code: {response.status_code}, response: {response.text}")
        return None


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token or is_token_expired(token):
            print("Token is missing or expired")
            return redirect(url_for('login_user'))
        return f(*args, **kwargs)
    return decorated


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"Error": "Unauthorized"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"Error": "Unauthorized"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"Error": "Unauthorized"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"Error": "Unauthorized"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"Error": "Unauthorized"}, 401)
        except Exception:
            raise AuthError({"Error": "Unauthorized"}, 401)

        return payload
    else:
        raise AuthError({"Error": "Unauthorized"}, 401)


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.route('/users/<int:user_id>/avatar', methods=['POST'])
@requires_auth
def upload_avatar(user_id):
    try:
        if 'file' not in request.files:
            return jsonify({"Error": "The request body is invalid"}), 400

        file_obj = request.files['file']

        user_key = client.key('users', user_id)
        user = client.get(user_key)
        if not user:
            return jsonify({"Error": "Not found"}), 404

        storage_client = storage.Client(project='tarpaulin')
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(f'users/{user_id}/avatar')
        blob.upload_from_file(file_obj, content_type='image/png')

        # Update the user entity with the avatar URL
        user_key = client.key('users', user_id)
        user = client.get(user_key)
        user['avatar_url'] = blob.public_url
        client.put(user)

        session['avatar_url'] = blob.public_url

        return redirect(url_for('profile'))
    except AuthError as e:
        return handle_auth_error(e)


@app.route('/users/<int:user_id>/avatar', methods=['GET'])
@requires_auth
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
        user_key = client.key('users', user_id)
        user = client.get(user_key)
        if not user:
            return jsonify({"Error": "Not found"}), 404

        # Check if the user is the owner of the avatar
        query = client.query(kind='users')
        results = list(query.fetch())
        for user in results:
            if user.key.id == user_id:
                if payload['sub'] != user['sub']:
                    return jsonify({"Error": "You don't have permission on this resource"}), 403

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(f'users/{user_id}/avatar')
        if not blob.exists():
            return jsonify({"Error": "Not found"}), 404

        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)

        return send_file(file_obj, mimetype='image/png', download_name=f'{user_id}.png'), 200
    except AuthError as e:
        return handle_auth_error(e)


@app.route('/postcourse', methods=['POST'])
@requires_auth
def post_course():
    try:
        required_attributes = ["subject", "number", "title", "instructor_id"]
        content = request.form.to_dict()

        missing_attributes = [attribute for attribute in required_attributes if attribute not in content]
        if missing_attributes:
            return jsonify({"Error": "The request body is invalid"}), 400

        user_key = client.key('users', int(content["instructor_id"]))
        user = client.get(user_key)

        new_course = datastore.entity.Entity(key=client.key('courses'))
        new_course.update({
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "instructor_id": int(content["instructor_id"])
        })
        client.put(new_course)

        if 'courses' in user:
            user['courses'].append(new_course.key.id)
        else:
            user['courses'] = [new_course.key.id]
        client.put(user)

        response = {
            "id": new_course.key.id,
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "instructor_id": content["instructor_id"],
            "self": f"https://{request.host}/courses/{new_course.key.id}"
        }

        return jsonify(response), 201
    except AuthError as e:
        return handle_auth_error(e)


@app.route('/courses/<int:course_id>', methods=['GET'])
@requires_auth
def get_course(course_id):
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if not course:
        return jsonify({"Error": "Not found"}), 404

    response = {
        "id": course.key.id,
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "instructor_id": course["instructor_id"],
        "self": f"https://{request.host}/courses/{course.key.id}"
    }

    return jsonify(response)


@app.route('/courses', methods=['GET'])
@requires_auth
def get_courses():
    limit = request.args.get('limit', default=20, type=int)

    query = client.query(kind='courses')
    courses = list(query.fetch(limit=limit))

    response_courses = []
    for course in courses:
        course_dict = {
            'id': course.key.id,
            'instructor_id': course['instructor_id'],
            'number': course['number'],
            'self': f"https://{request.host}/courses/{course.key.id}",
            'subject': course['subject'],
            'title': course['title']
        }
        response_courses.append(course_dict)

    response = {
        'courses': response_courses
    }

    return jsonify(response)


@app.route('/courses/<int:course_id>', methods=['PATCH'])
@requires_auth
def update_course(course_id):
    if check_admin_role(session['sub']):
        try:
            content = request.form.to_dict()
            course_key = client.key('courses', course_id)
            course = client.get(course_key)

            if course is None:
                return jsonify({"Error": "Course not found"}), 404

            if 'subject' in content:
                course['subject'] = content['subject']
            if 'number' in content:
                course['number'] = content['number']
            if 'title' in content:
                course['title'] = content['title']
            if 'term' in content:
                course['term'] = content['term']

            if 'instructor_id' in content and content['instructor_id'] != str(course['instructor_id']):
                # Get the old instructor's key
                old_instructor_key = client.key('users', int(course['instructor_id']))
                old_instructor = client.get(old_instructor_key)

                # Get the new instructor's key
                new_instructor_key = client.key('users', int(content['instructor_id']))
                new_instructor = client.get(new_instructor_key)
                if new_instructor is None or new_instructor['role'] != 'instructor':
                    return jsonify({"Error": "The request body is invalid"}), 400

                # Remove the course from the old instructor's courses array
                if old_instructor and 'courses' in old_instructor:
                    old_instructor['courses'].remove(course_id)
                    client.put(old_instructor)

                # Add the course to the new instructor's courses array
                if 'courses' in new_instructor:
                    new_instructor['courses'].append(course_id)
                else:
                    new_instructor['courses'] = [course_id]
                client.put(new_instructor)

                # Update the course's instructor_id
                course['instructor_id'] = int(content['instructor_id'])

            client.put(course)

            updated_course = {
                'id': course.key.id,
                'instructor_id': int(course['instructor_id']),
                'number': course['number'],
                'self': f"https://{request.host}/courses/{course.key.id}",
                'subject': course['subject'],
                'title': course['title']
            }

            return updated_course, 200
        except AuthError as e:
            return handle_auth_error(e)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
@requires_auth
def update_enrollment(course_id, add_students, remove_students):
    if session.get('role') == 'student':
        try:
            course_key = client.key('courses', course_id)
            course = client.get(course_key)

            if course is None:
                return jsonify({"Error": "You don't have permission on this resource"}), 403

            # Validate that there is no common value between add and remove
            if set(add_students) & set(remove_students):
                return jsonify({"Error": "Enrollment data is invalid"}), 409

            # Fetch all users
            user_query = client.query(kind='users')
            all_users = list(user_query.fetch())

            # Filter to get valid student IDs
            valid_student_ids = {user.key.id for user in all_users if user['role'] == 'student'}

            # Validate that all values in add and remove correspond to student users
            student_ids = set(add_students + remove_students)
            if not student_ids <= valid_student_ids:
                return jsonify({"Error": "Enrollment data is invalid"}), 409

            # Update student enrollments
            for user in all_users:
                if user.key.id in add_students and course_id not in user.get('courses', []):
                    user['courses'] = user.get('courses', []) + [course_id]
                    client.put(user)
                elif user.key.id in remove_students and course_id in user.get('courses', []):
                    user['courses'].remove(course_id)
                    client.put(user)

            return '', 200
        except AuthError as e:
            return handle_auth_error(e)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/courses/<int:course_id>/students', methods=['GET'])
@requires_auth
def get_enrollment(course_id):
    if session.get('role') == 'instructor':
        try:
            course_key = client.key('courses', course_id)
            course = client.get(course_key)

            if course is None:
                return jsonify({"Error": "Course not found"}), 404

            if session.get('role') != 'instructor':
                return jsonify({"Error": "You don't have permission on this resource"}), 403

            # Fetch all users
            user_query = client.query(kind='users')
            all_users = list(user_query.fetch())

            # Get students enrolled in the course with their grades
            enrolled_students = [
                {
                    'id': user.key.id,
                    'avatar_url': user.get('avatar_url', None),
                    'grade': next((grade.split(': ')[1] for grade in user.get('grades', []) if grade.startswith(f'{course_id}: ')), '')
                }
                for user in all_users if user['role'] == 'student' and course_id in user.get('courses', [])
            ]

            for user in enrolled_students:
                user_info = get_user_info(int(user['id']))
                auth0_user = get_auth0_user_info(user_info.get('sub'))
                user['name'] = auth0_user.get('email')

            return jsonify(enrolled_students), 200

        except AuthError as e:
            return handle_auth_error(e)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/', methods=['POST'])
def login_user():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash('Username and password required')
        return render_template('index.html', error="The request body is invalid"), 400

    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }

    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    response = requests.post(url, json=body, headers=headers)

    if response.status_code != 200:
        flash('Username and/or password are incorrect. Please try again.')
        return redirect(url_for('login_user'))

    token = response.json().get("id_token")

    session['token'] = token

    class NewRequest:
        headers = {
            'Authorization': f'Bearer {token}'
        }

    new_request = NewRequest()

    payload = verify_jwt(new_request)
    sub = payload['sub']
    user_query = client.query(kind='users')
    users = list(user_query.fetch())
    for user in users:
        if user['sub'] == sub:
            role = user['role']
            session['role'] = role
            session['user_id'] = user.key.id
            session['name'] = username
            session['sub'] = user['sub']
            session['api_token'] = get_management_token()
            return redirect(url_for('home'))

    return render_template('index.html', error="User not found"), 404


def get_management_token():
    conn = http.client.HTTPSConnection(DOMAIN)

    payload = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'audience': f'https://{DOMAIN}/api/v2/'
    }

    headers = {'content-type': "application/json"}

    conn.request("POST", "/oauth/token", json.dumps(payload), headers)

    res = conn.getresponse()
    data = res.read()
    token_response = json.loads(data)
    return token_response.get('access_token')


def check_admin_role(sub):
    query = client.query(kind='users')
    results = list(query.fetch())

    for user in results:
        if user['role'] == 'admin':
            if user['sub'] == sub:
                return True

    raise AuthError({"Error": "You don't have permission on this resource"}, 403)


@app.route('/users/<int:user_id>', methods=['GET'])
@requires_auth
def get_user(user_id):
    try:
        # Check if the user is an admin or the user itself
        user_key = client.key('users', user_id)
        user = client.get(user_key)

        response = {
            'id': user.key.id,
            'role': user['role'],
            'sub': user['sub']
        }
        if 'avatar_url' in user:
            response['avatar_url'] = user['avatar_url']
        if user['role'] in ['instructor', 'student']:
            response['courses'] = user.get('courses', [])

        return jsonify(response), 200
    except AuthError as e:
        return handle_auth_error(e)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/home')
@requires_auth
def home():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_user'))

    user_info = get_user_info(user_id)
    if not user_info:
        return redirect(url_for('login_user'))

    role = user_info['role']
    return render_template('home.html', role=role, user_info=user_info)


@app.route('/profile')
@requires_auth
def profile():
    user = get_auth0_user_info(session.get('sub'))
    user_date = user.get('created_at')
    day = user_date.replace('Z', '')
    # Define the format of the input timestamp
    input_format = "%Y-%m-%dT%H:%M:%S.%f"
    # Parse the timestamp string into a datetime object
    date_obj = datetime.strptime(day, input_format)
    # Define the desired output format
    output_format = "%m-%d-%Y"
    # Format the datetime object into the desired string representation
    formatted_date = date_obj.strftime(output_format)
    # Fetch user info from the session or database
    user_info = get_user_info(session['user_id'])
    return render_template('profile.html', user_info=user_info, created_at=formatted_date)


def get_user_info(user_id):
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if not user:
        return None

    return {
        'user_id': user.key.id,
        'name': session.get('name'),
        'role': user['role'],
        'sub': user['sub'],
        'grades': user.get('grades', None),
        'courses': user.get('courses', None),
        'avatar_url': user.get('avatar_url', None),
        'timestamp': datetime.now().timestamp()
    }


@app.route('/enroll')
@requires_auth
def get_available_courses():
    if session.get('role') != 'student':
        redirect(url_for('home'))
        return ({"Error": "Unauthorized"}), 401
    else:
        user = get_user_info(session['user_id'])
        user_course_ids = user.get('courses', [])

        # Fetch all course IDs
        all_course_keys = client.query(kind='courses').fetch()
        all_course_ids = [course_key.key.id for course_key in all_course_keys]

        # Fetch available courses and their instructors, excluding user's current courses
        available_courses, instructor_info_map = fetch_courses_and_instructors(all_course_ids, exclude_ids=user_course_ids)

        for course in available_courses:
            instructor_info = instructor_info_map.get(course['instructor_id'], {})
            course['instructor_name'] = instructor_info.get('name', 'Unknown')

        return render_template('enroll.html', courses=available_courses, student=session.get('user_id'))


@app.route('/yourcourses')
@requires_auth
def get_user_courses():
    if session.get('role') == 'instructor' or session.get('role') == 'student':
        user = get_user_info(session['user_id'])
        user_course_ids = user.get('courses', [])

        # Fetch user courses and their instructors
        user_courses, instructor_info_map = fetch_courses_and_instructors(user_course_ids)

        for course in user_courses:
            instructor_info = instructor_info_map.get(course['instructor_id'], {})
            course['instructor_name'] = instructor_info.get('name', 'Unknown')
            if user.get('role') == 'student':
                user_grades = user.get('grades') or []
                grade_entry = next((g for g in user_grades if g.startswith(f"{course.key.id}: ")), None)
                if grade_entry:
                    course['grade'] = grade_entry.split(": ")[1]  # Get the grade letter
                else:
                    course['grade'] = "-"  # No grade found

        return render_template('courses.html', courses=user_courses, role=session.get('role', ''))

    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/enroll/<int:course_id>')
@requires_auth
def enroll_in_course(course_id):
    user_id = session['user_id']
    response, status_code = update_enrollment(course_id, [user_id], [])
    if status_code == 200:
        return redirect(url_for('get_available_courses'))
    else:
        return render_template('error.html', error=response.json().get('Error', 'Unknown error'))


@app.route('/drop/<int:course_id>')
@requires_auth
def drop_course(course_id):
    user_id = session['user_id']
    response, status_code = update_enrollment(course_id, [], [user_id])
    if status_code == 200:
        return redirect(url_for('get_user_courses'))
    else:
        return render_template('error.html', error=response.json().get('Error', 'Unknown error'))


def fetch_courses_and_instructors(course_ids, exclude_ids=None):
    if exclude_ids is None:
        exclude_ids = []

    filtered_course_ids = []
    # Filter out excluded course IDs
    if course_ids is not None:
        filtered_course_ids = [course_id for course_id in course_ids if course_id not in exclude_ids]

    if not filtered_course_ids:
        return [], {}

    # Fetch all courses in a single query
    course_keys = [client.key('courses', course_id) for course_id in filtered_course_ids]
    courses = client.get_multi(course_keys)

    # Fetch all instructors in a single query
    instructor_ids = {course['instructor_id'] for course in courses}
    instructor_keys = [client.key('users', instructor_id) for instructor_id in instructor_ids]
    instructors = client.get_multi(instructor_keys)

    instructor_info_map = {}
    for instructor in instructors:
        instructor_info = get_auth0_user_info(instructor['sub'])
        instructor_info_map[instructor.key.id] = instructor_info

    return courses, instructor_info_map


@app.route('/modifycourse')
@requires_auth
def modify_courses():
    if check_admin_role(session['sub']):
        courses_response = get_courses()
        courses = courses_response.get_json().get('courses')

        # Fetch all instructors in one query
        instructor_ids = {int(course['instructor_id']) for course in courses}
        instructor_keys = [client.key('users', instructor_id) for instructor_id in instructor_ids]
        instructors = client.get_multi(instructor_keys)

        # Map instructor IDs to instructor names
        instructor_info_map = {}
        for instructor in instructors:
            instructor_info = get_auth0_user_info(instructor['sub'])
            instructor_info_map[instructor.key.id] = instructor_info.get('name', 'Unknown')

        # Assign instructor names to courses
        for course in courses:
            course['instructor_name'] = instructor_info_map.get(int(course['instructor_id']), 'Unknown')

        return render_template('modify_course.html', courses=courses)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/modifycourse/<int:course_id>')
@requires_auth
def modify_course_form(course_id):
    if check_admin_role(session['sub']):
        course_response = get_course(course_id)
        course = course_response.get_json()
        instructor = get_user_info(int(course['instructor_id']))
        instructor_sub = instructor['sub']
        instructor_info = get_auth0_user_info(instructor_sub)
        course['name'] = instructor_info.get('name', 'Unknown')
        instructors = get_all_instructors()
        return render_template('modify_course_form.html', course=course, instructors=instructors)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/modifycourse/<int:course_id>', methods=['POST'])
@requires_auth
def modify_course(course_id):
    if check_admin_role(session['sub']):
        response, status_code = update_course(course_id)
        if status_code == 200:
            return redirect(url_for('modify_courses'))
        else:
            course_response = get_course(course_id)
            course = course_response.get_json()
            return render_template('modify_course_form.html', course=course, error=response.get_json().get('Error'))
    else:
        return ({"Error": "Unauthorized"}), 401


def get_all_instructors():
    query = client.query(kind='users')
    result = list(query.fetch())
    instructor_list = []
    for user in result:
        if user['role'] == 'instructor':
            instructor_info = get_auth0_user_info(user['sub'])
            if instructor_info:
                instructor_list.append({
                    'id': user.key.id,
                    'name': instructor_info.get('name', 'Unknown')
                })
    return instructor_list


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_user'))


@app.route('/register', methods=['POST'])
def register_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    session['api_token'] = get_management_token()

    # Create user in Auth0
    user_info = create_auth0_user(username, password, role)
    if not user_info:
        flash('Registration failed. Ensure username and password requirements are met.')
        return redirect(url_for('login_user'))

    # Retrieve user's sub from Auth0
    user_sub = user_info['user_id']

    # Update Datastore with the new user's info
    user_key = client.key('users')
    new_user = datastore.Entity(key=user_key)
    new_user.update({
        'sub': user_sub,
        'role': role
    })
    client.put(new_user)

    # Log in the newly registered user
    return login_user()


def create_auth0_user(username, password, role):
    url = f'https://{DOMAIN}/api/v2/users'
    token = session.get('api_token')

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    payload = {
        'email': username,
        'password': password,
        'connection': 'Username-Password-Authentication'
    }

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        return response.json()
    else:
        print(f"Failed to create user: {response.status_code}, {response.text}")
        return None


@app.route('/createcourse')
@requires_auth
def create_course_form():
    if session.get('role') == 'admin':
        instructors = get_all_instructors()
        return render_template('createcourse.html', instructors=instructors)
    else:
        return ({"Error": "Unauthorized"}), 401


@app.route('/createcourse', methods=['POST'])
@requires_auth
def create_course():
    response, status_code = post_course()
    if status_code == 201:
        flash('Course created successfully')
        return redirect(url_for('create_course_view'))
    else:
        instructors = get_all_instructors()
        return render_template('createcourse.html', instructors=instructors, error=response.get_json().get('Error'))


@app.route('/createcourse', methods=['GET'])
@requires_auth
def create_course_view():
    instructors = get_all_instructors()
    return render_template('createcourse.html', instructors=instructors)


@app.route('/courses/<int:course_id>/grades', methods=['PATCH'])
@requires_auth
def update_grades(course_id):
    try:
        data = request.get_json()
        grades = data.get('grades')

        if not grades:
            return jsonify({"Error": "The request body is invalid"}), 400

        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if course is None:
            return jsonify({"Error": "Course not found"}), 404

        for student_id, grade in grades.items():
            user_key = client.key('users', int(student_id))
            user = client.get(user_key)
            if not user or user['role'] != 'student':
                return jsonify({"Error": f"Student with ID {student_id} not found"}), 404

            user_grades = user.get('grades', [])
            user_grades = [g for g in user_grades if not g.startswith(f"{course_id}: ")]
            user_grades.append(f"{course_id}: {grade}")
            user['grades'] = user_grades
            client.put(user)

        flash('Grades submitted successfully')
        return ({"message": "Grades submitted successfully"}), 200

    except AuthError as e:
        return handle_auth_error(e)
    except Exception as e:
        return jsonify({"Error": str(e)}), 500


@app.route('/gradebook')
@requires_auth
def load_gradebook():
    if session.get('role') != 'instructor':
        return ({"Error": "Unauthorized"}), 401
    else:
        instructor = get_user_info(int(session.get('user_id')))
        instructor_course_ids = instructor.get('courses', [])

        # Fetch course details for each course ID
        instructor_courses = []
        for course_id in instructor_course_ids:
            course_key = client.key('courses', course_id)
            course = client.get(course_key)
            if course:
                instructor_courses.append(course)

        return render_template('grades.html', courses=instructor_courses)


@app.route('/directory')
@requires_auth
def load_directory():
    user_list = []
    query = client.query(kind='users')
    users = list(query.fetch())

    for user in users:
        avatar = user.get('avatar_url', None)
        auth0_user = get_auth0_user_info(user.get('sub'))
        if auth0_user:
            name = auth0_user.get('name')
            role = user['role']  # Assuming role is stored in Datastore user entity
            user_list.append({'avatar': avatar, 'name': name, 'role': role})

    return render_template('directory.html', users=user_list)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
