from flask import Flask, request, send_file, jsonify, url_for
from google.cloud import storage, datastore
from google.cloud.datastore import query  # filters on datastore queries
from google.cloud.datastore.query import PropertyFilter
import io
import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth


USERS = 'users'
COURSES = 'courses'
IMAGES = 'images'

PHOTO_BUCKET='assignment-6-reynemil'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()
# auth0 passwords: 1234azula!

# Update the values of the following 3 variables
CLIENT_ID = 'LGE7ksR49TvL0X6vk1UPUftZkwSCVjkz'
CLIENT_SECRET = 'zwX_haY8ma_B0zq5ZXxBVeE0QoaNJvTqENJtK_ni2RgJrp4Xg-SXw0zwFjBUpKf3'
DOMAIN = 'dev-31mjqme4080c5nan.us.auth0.com'

domain = 'https://assignment-6-reynemil.wl.r.appspot.com'

# describes the way the jwt is gonna be encoded
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
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
# function given to us in class
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({'Error': 'Unauthorized'}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({'Error': 'Unauthorized'}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({'Error': 'Unauthorized'}, 401)
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
            raise AuthError({'Error': '103Unauthorized'}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({'Error': '105Unauthorized'}, 401)
        except Exception:
            raise AuthError({'Error': '107Unauthorized'}, 401)

        return payload
    else:
        raise AuthError({'Error': 'Unauthorized'}, 401)


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if content is None or "username" not in content or "password" not in content:
        return jsonify({'Error': 'The request body is invalid'}), 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
           }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    # Assuming the JWT token is available in the response JSON
    response_json = r.json()
    jwt = response_json.get('id_token', None)

    if jwt:
        return jsonify({'token': jwt}), 200
    else:
        return jsonify({'Error': 'Unauthorized'}), 401



# takes jwt in header
@app.route('/users', methods =['GET'])
def get_all_users():
    # get jwt from request to get 'sub' from request to check if it's admin sub

    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('role', '=', 'admin'))
    admin = list(query.fetch())

    if sub == admin[0]['sub']:
        query = client.query(kind=USERS)
        users = list(query.fetch())
        for u in users:
            u['id'] = u.key.id
        return users

    else:
        return jsonify({'Error': "You don't have permission on this resource"}), 403


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """If jwt from admin, will always return, else jwt needs to be same as the user_id being searched"""
    if check_admin(request):  # does request come from admin
        query = client.query(kind=USERS)
        users = list(query.fetch())
        for u in users:
            u['id'] = u.key.id
            if u['id'] == user_id:
                if u['role'] == 'student':
                    urls = student_courses(user_id)
                    u['courses'] = urls
                    avatar = avatars(user_id)
                    if avatar is not None and len(avatar) !=0:
                        u['avatar_url'] = avatar
                    return u, 200

                if u['role'] == 'instructor':
                    urls = instructor_courses(user_id)
                    u['courses'] = urls
                    avatar = avatars(user_id)
                    if avatar is not None and len(avatar) != 0:
                        u['avatar_url'] = avatar
                    return u, 200

                if u['role'] == 'admin':
                    avatar = avatars(user_id)
                    if avatar is not None and len(avatar) != 0:
                        u['avatar_url'] = avatar
                    return u, 200

        return jsonify({'Error': "You don't have permission on this resource"}), 403 # user_id doesn't exist


    else:     # check if user_id is same as in jwt
        payload = verify_jwt(request)
        sub = payload["sub"]
        query = client.query(kind=USERS)
        users = list(query.fetch())
        for u in users:
            if sub == u['sub'] and u.key.id == user_id:  # jwt and user_id match
                u['id'] = u.key.id
                if u['id'] == user_id:     # found the user we are looking for
                    if u['role'] == 'student':
                        urls = student_courses(user_id)
                        u['courses'] = urls
                        avatar = avatars(user_id)
                        if avatar is not None and len(avatar) != 0:
                            u['avatar_url'] = avatar
                        return u, 200
                    if u['role'] == 'instructor':
                        urls = instructor_courses(user_id)
                        u['courses'] = urls
                        avatar = avatars(user_id)
                        if avatar is not None and len(avatar) != 0:
                            u['avatar_url'] = avatar
                        return u, 200
                    if u['role'] == 'admin':
                        avatar = avatars(user_id)
                        if avatar is not None and len(avatar) != 0:
                            u['avatar_url'] = avatar
                        return u, 200
        return jsonify({'Error': "You don't have permission on this resource"}), 403  # user_id doesn't exist or doesn't match jwt



def student_courses(student_id):
    """helper function to @app.route('/users/<int:user_id>', methods=['GET'])
        Returns a list of course urls of courses student is enrolled in"""
    urls = []
    query = client.query(kind=COURSES)
    courses = list(query.fetch())
    for course in courses:
        course['id'] = course.key.id
        if student_id in course['students']:
            url = domain + '/courses/' + str(course['id'])
            urls.append(url)
    return urls


def instructor_courses(instructor_id):
    """helper function to @app.route('/users/<int:user_id>', methods=['GET'])
            Returns a list of course urls instructor is teaching"""
    urls = []
    query = client.query(kind=COURSES)
    courses = list(query.fetch())
    for course in courses:
        course['id'] = course.key.id
        if instructor_id == course['instructor_id']:
            url = domain + '/courses/' + str(course['id'])
            urls.append(url)
    return urls

def avatars(user_id):
    """helperfunction to @app.route('/users/<int:user_id>', methods=['GET'])
        returns url of avatar if they have one"""
    query = client.query(kind=IMAGES)
    images = list(query.fetch())
    for image in images:
        image['id'] = image.key.id
        if user_id == image['user_id']:
            return domain + '/users/' + str(user_id) + '/avatar'




def check_admin(request):
    """returns true if the request contains a jwt from an admin"""
    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('role', '=', 'admin'))
    admin = list(query.fetch())

    if sub == admin[0]['sub']: #property 'sub' of first admin entry in list
        return True
    return False




# Create a course if the Authorization header contains a valid JWT for admin
@app.route('/courses', methods= ['POST'])
def create_course():

    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('role', '=', 'admin'))
    admin = list(query.fetch())

    if sub == admin[0]['sub']:  # is an admin jwt
        content = request.get_json()
        if len(content) != 5:
            return jsonify({'Error': 'The request body is invalid'}), 400
        # return check_instructors(content['instructor_id']) when debugging
        if check_instructors(content['instructor_id']):
            new_course = datastore.Entity(key=client.key(COURSES))
            new_course.update({"subject": content["subject"], "number": content['number'], "title": content["title"], "term": content["term"], "instructor_id": content["instructor_id"], "students": []})
            client.put(new_course)
            # get id from datastore
            new_course['id'] = new_course.key.id
            new_course['self'] = domain + '/courses/' + str(new_course['id'])
            del new_course['students']
            return (new_course, 201)
        else:
            return jsonify({'Error': 'The request body is invalid'}), 400
    else:
        return jsonify({'Error': "You don't have permission on this resource"}), 403


@app.route('/courses', methods=['GET'])
def get_courses():
    # Get limit and offset from request query parameters
    limit = request.args.get('limit')
    offset = request.args.get('offset')

    # Convert limit and offset to integers
    limit = int(limit) if limit else 3
    offset = int(offset) if offset else 0

    # Create a query to fetch courses
    query = client.query(kind=COURSES)
    query.order = ['subject']

    # Fetch courses with the specified limit and offset
    l_iterator = query.fetch(limit=limit, offset=offset)
    pages = l_iterator.pages
    results = list(next(pages))

    for course in results:
        del course['students']
        course['id'] = course.key.id
        course['self'] = domain + '/courses/' + str(course['id'])

    # Check if there are more courses
    next_offset = offset + limit
    next_url = url_for('get_courses', limit=limit, offset=next_offset, _external=True) if len(results) == limit else None
    url = (domain + 'courses?limit=' + str(limit) + '&offset=' + str(offset)) if len(results) == limit else None
    # Construct JSON response
    response = {
        'courses': results,
        'next': next_url
    }

    # Return the JSON response
    return jsonify(response), 200



@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    if request.method == 'GET':
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # checks to make sure course exists
        if course is None:
            return {"Error": "Not found"}, 404
        else:
            course['id'] = course_id
            course["self"] = domain + '/courses/' + str(course['id'])
            del course["students"]       # makes sure enrolled students aren't included in properties
            return course, 200


@app.route('/courses/<int:course_id>', methods=["PATCH"])
def edit_course(course_id):
    content = request.get_json()

    if check_admin(request):
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # checks to make sure course exists
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403

        if 'instructor_id' in content:
            if check_instructors(content['instructor_id']):  # valid instructor id
                for property_name, value in content.items():
                    course[property_name] = value
                client.put(course)
                del course['students']
                course['id'] = course_id
                course['self'] = domain + '/courses/' + str(course['id'])
                return course, 200
            else:   # instructor_id doesn't exist
                return jsonify({'Error': 'The request body is invalid'}), 400

        else:  # instructor_id not in content
            for property_name, value in content.items():
                course[property_name] = value
            client.put(course)
            del course['students']
            course['id'] = course_id
            course['self'] = domain + '/courses/' + str(course['id'])
            return course, 200

    else:    # doesn't belong to an admin
        return jsonify({'Error': "You don't have permission on this resource"}), 403



@app.route('/courses/<int:course_id>', methods=["DELETE"])
def delete_course(course_id):
    if check_admin(request):   # is admin
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # checks to make sure course exists
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403  # course doesn't exist

        client.delete(course_key)  # delete from datastore
        return '', 204



    else:
        return jsonify({'Error': "You don't have permission on this resource"}), 403  # not admin






@app.route('/courses/<int:course_id>/students', methods=["PATCH"])
def edit_enrollment(course_id):
    content = request.get_json()
    if check_admin(request):   # is admin
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403  # course doesn't exist
        if check_enrollement_params(content):    #request params are valid
            edit_course_enrollment(content, course_id)
            return '', 200

        else:                   # request params invalid
            return jsonify({"Error": "Enrollment data is invalid"}), 409
    else:   # check if instructor of course
        payload = verify_jwt(request)
        sub = payload["sub"]

        query = client.query(kind=USERS)
        query.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        instructors = list(query.fetch())      #list of all instructors

        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403  # course doesn't exist
        course_instructor_id = course['instructor_id']   #find id of instructor teaching course

        for i in instructors:
            if sub == i['sub'] and i.key.id == course_instructor_id:  # it's an instructor and instructor teaches this class
                if check_enrollement_params(content):
                    edit_course_enrollment(content, course_id)
                    return '', 200
                else:
                    return jsonify({"Error": "Enrollment data is invalid"}), 409

        return jsonify({'Error': "You don't have permission on this resource"}), 403 # neither admin nor right instructor



def check_enrollement_params(content):
    """helper for @app.route('/course/<int:course_id>/students', methods=["PATCH"])
       Makes sure add and remove params have only student ids and they don't share any ids
       Returns true if enrollment data is valid"""
    students = []
    removes = []
    for num in content['add']:
        if not check_students(num):  # calls error if num isn't a student id
            return False
        students.append(num)
    for num in content['remove']:
        if not check_students(num):  # calls error if num isn't a student id
            return False
        removes.append(num)
    if check_lists(students, removes):  # calls error if num on both lists
        return False
    return True


def edit_course_enrollment(content, course_id):
    """helper for @app.route('/course/<int:course_id>/students', methods=["PATCH"])
        actually adds and removes students from course['students']"""

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    for num in content['add']:
        if num not in course['students']:
            course['students'].append(num)
            client.put(course)
    for num in content['remove']:
        if num in course['students']:
            course['students'].remove(num)
            client.put(course)    # actually changes the database
                                # TODO probably why avatars weren't deleting properly



def check_lists(list1, list2):
    """Returns True if lists have an element in common"""
    common_elements = set(list1) & set(list2)
    return bool(common_elements)


def check_instructors(instructor_id):
    """checks if arg id belongs to an instructor. Returns true if it does, and false otherwise"""
    query = client.query(kind=USERS)
    all_users = list(query.fetch())
    all_instructors = []
    # users only have properties 'role' and 'sub' [{"role": "student", "sub":"auth03784937"}, {.....}]
    for u in all_users:
        if u['role'] == 'instructor' and u.key.id == instructor_id: # use u.key.id bc there is no id in properties
            return True
    return False
    # return all_instructors when debugging

def check_students(student_id):
    """helper function for check_enrollment_params(num)
        Returns True if id belongs to a student"""
    query = client.query(kind=USERS)
    all_users = list(query.fetch())
    for u in all_users:
        if u['role'] == 'student' and u.key.id == student_id:
            return True
    return False

@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_course_enrollment(course_id):
    if check_admin(request):  # is admin
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403  # course doesn't exist
        return course['students'], 544

    else:         # check if instructor of course
        payload = verify_jwt(request)
        sub = payload["sub"]

        query = client.query(kind=USERS)
        query.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        instructors = list(query.fetch())  # list of all instructors

        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return jsonify({'Error': "You don't have permission on this resource"}), 403  # course doesn't exist

        course_instructor_id = course['instructor_id']  # id of instructor teaching course
        for i in instructors:
            if sub == i['sub'] and i.key.id == course_instructor_id:  # it's an instructor and instructor teaches this class
                return course['students'], 562

        return jsonify({'Error': "You don't have permission on this resource"}), 403  # neither admin nor right instructor








@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def create_avatar(user_id):
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'

    if 'file' not in request.files:
        return jsonify({'Error': 'The request body is invalid'}), 400

    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    users = list(query.fetch())
    for u in users:
        if sub == u['sub'] and u.key.id == user_id:
            # Set file_obj to the file sent in the request
            file_obj = request.files['file']

            avatar = avatars(user_id)
            if avatar is not None and len(avatar) != 0:   # user has an avatar already
                delete_avatar_helper(user_id)             # delete old image from datastore
            # If the multipart form data has a part with name 'tag', set the
            # value of the variable 'tag' to the value of 'tag' in the request.
            # Note we are not doing anything with the variable 'tag' in this
            # example, however this illustrates how we can extract data from the
            # multipart form data in addition to the files.
            request_data = dict(request.form)
            request_data['tag'] = user_id  # Add user_id as the tag
            request.form = request_data          #add user_id as the tag
            # Create a storage client
            storage_client = storage.Client()
            # Get a handle on the bucket
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            # Create a blob object for the bucket with the name of the file
            blob = bucket.blob(file_obj.filename)
            # Position the file_obj to its beginning
            file_obj.seek(0)
            # Upload the file into Cloud Storage
            blob.upload_from_file(file_obj)
            new_image = datastore.Entity(key=client.key(IMAGES))
            new_image.update({"user_id": user_id, "filename": file_obj.filename})
            client.put(new_image)

            return jsonify({'avatar_url': domain + '/users/' + str(user_id) + '/avatar'}), 200

    # jwt doesn't match user_id
    return jsonify({'Error': "You don't have permission on this resource"}), 403



    return ({'file_name': file_obj.filename},201)


def delete_avatar_helper(user_id):
    """Helper to @app.route('/users/<int:user_id>/avatar', methods=['POST'])
        deletes avatar if user_id already has one"""
    query = client.query(kind=IMAGES)
    images = list(query.fetch())
    for image in images:
        image['id'] = image.key.id
        if user_id == image['user_id']:
            file_name = image['filename']
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            blob = bucket.blob(file_name)
            # Delete the file from Cloud Storage
            blob.delete()
            # delete entity from datastore
            image_key = client.key(IMAGES, image['id'])
            client.delete(image_key)  # deletes avatar image from bucket





@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    users = list(query.fetch())
    for u in users:
        if sub == u['sub'] and u.key.id == user_id:

            query = client.query(kind=IMAGES)
            images = list(query.fetch())
            for image in images:
                image['id'] = image.key.id
                if user_id == image['user_id']:
                    file_name = image['filename']
                    storage_client = storage.Client()
                    bucket = storage_client.get_bucket(PHOTO_BUCKET)
                    # Create a blob with the given file name
                    blob = bucket.blob(file_name)
                    # Create a file object in memory using Python io package
                    file_obj = io.BytesIO()
                    # Download the file from Cloud Storage to the file_obj variable
                    blob.download_to_file(file_obj)
                    # Position the file_obj to its beginning
                    file_obj.seek(0)
                    # Send the object as a file in the response with the correct MIME type and file name
                    return send_file(file_obj, mimetype='image/x-png', download_name=file_name), 200

            return {"Error": "Not found"}, 404  # user doesn't have an avatar

    return jsonify({'Error': "You don't have permission on this resource"}), 403

# TODO handle if there's no avatar we're trying to delete
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    payload = verify_jwt(request)
    sub = payload["sub"]
    query = client.query(kind=USERS)
    users = list(query.fetch())
    for u in users:
        if sub == u['sub'] and u.key.id == user_id:     # jwt is user_id
            """if 'avatar_url' in u:  # Check if 'avatar_url' key exists
                del u['avatar_url']  # Delete 'avatar_url' from user entity  # TODO i think these don't do anything
                client.put(u)"""
            query = client.query(kind=IMAGES)
            images = list(query.fetch())
            for image in images:
                image['id'] = image.key.id
                if user_id == image['user_id']:
                    file_name = image['filename']
                    storage_client = storage.Client()
                    bucket = storage_client.get_bucket(PHOTO_BUCKET)
                    blob = bucket.blob(file_name)
                    # Delete the file from Cloud Storage
                    blob.delete()
                    # delete entity from datastore
                    image_key = client.key(IMAGES, image['id'])
                    client.delete(image_key)  #deletes avatar image from bucket


                    return '',204
            return {"Error": "Not found"}, 404  # user doesn't have an avatar
    return jsonify({'Error': "You don't have permission on this resource"}), 403

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)