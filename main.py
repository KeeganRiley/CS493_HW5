from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BUSINESSES = "businesses"
ERROR_MISSING_ATTRIBUTE = {"Error": "The request body is missing at least one of the required attributes"}
ERROR_BUSINESS_NOT_FOUND = {"Error": "No business with this business_id exists"}

# Update the values of the following 3 variables
CLIENT_ID = 'NOkJU0RZwqdTDAejJ9eKBdgEoJ8nAIW8'
CLIENT_SECRET = 'UAE3jm0QXJfgHOC-Awa2BbpivUl3EXQWOHdDRQViK2cU7A1uJj4MCfMyfF2HrNHI'
DOMAIN = 'dev-ousejjqdschxbglu.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

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

def missing_attr(content, required_attributes):
    """Helper function to verify required number of attributes."""
    for attribute in required_attributes:
        if attribute not in content:
            return True
    return False

def get_hostname():
    """Return the hostname url including the scheme."""
    return request.host_url.strip('/')

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
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
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API"\

# Create a business if the Authorization header contains a valid JWT
@app.route('/businesses', methods=['POST'])
def post_business():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_business = datastore.entity.Entity(key=client.key(BUSINESSES))
        new_business.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_business)
        return jsonify(id=new_business.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Endpoint 3. Create a business.
@app.route('/' + BUSINESSES, methods=['POST'])
def post_businesses():
    """Allows you to create a new business."""
    req_attr = ['name', 'street_address', 'city', 'state', 'zip_code', 'inspection_score']
    content = request.get_json()
    if missing_attr(content, req_attr):
        return ERROR_MISSING_ATTRIBUTE, 400

    if request.method == 'POST':
        payload = verify_jwt(request)

        new_key = client.key(BUSINESSES)
        new_business = datastore.Entity(key=new_key)
        new_business.update({
            'owner_id': payload['sub'],
            'name': content['name'],
            'street_address': content['street_address'],
            'city': content['city'],
            'state': content['state'],
            'zip_code': content['zip_code'],
            'inspection_score': content['inspection_score']
        })
        client.put(new_business)

        # Append id, owner_id, and self (url) for response.
        new_business['id'] = new_business.key.id
        # new_business['owner_id'] = payload["sub"]
        self_url = get_hostname() + '/' + BUSINESSES + str(new_business['id'])
        new_business['self'] = self_url
        return new_business, 201
    else:
        return jsonify(error='Method not recogonized')


# Endpoint 4. Get a business.
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['GET'])
def get_business(business_id):
    """Allows you to get an existing business."""
    # Check business exists.
    if request.method == 'POST':
        payload = verify_jwt(request)

        business_key = client.key(BUSINESSES, business_id)
        business = client.get(key=business_key)
        if business is None:
            return ERROR_BUSINESS_NOT_FOUND, 403

        business['id'] = business.key.id
        self_url = get_hostname() + '/' + BUSINESSES + str(business['id'])
        business['self'] = self_url

        return business
    else:
        return jsonify(error='Method not recogonized')


# Endpoint 5. List businesses.
@app.route('/' + BUSINESSES, methods=['GET'])
def get_businesses():
    """List the businesses for an owner, or all businesses."""
    # If JWT is valid and included.
    if request.method == 'POST':
        payload = verify_jwt(request)
        query = client.query(kind=BUSINESSES)
        query.add_filter('owner_id', '=', payload['sub'])

        results = list(query.fetch())
        for business in results:
            business['id'] = business.key.id
            self_url = get_hostname() + '/' + BUSINESSES + str(business['id'])
            business['self'] = self_url

    # If JWT is invalid or not included.
    else:
        query = client.query(kind=BUSINESSES)
        results = list(query.fetch())
        for business in results:
            business['id'] = business.key.id
            self_url = get_hostname() + '/' + BUSINESSES + str(business['id'])
            business['self'] = self_url
            del business['inspection_score']

    return results if results is not None else []

# Endpoint 6. Delete a business, also deletes any reviews written for this business.
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['DELETE'])
def delete_business(business_id):
    """Allows you to delete a business. 
    
    Note that if there are any reviews for a business, deleting the business
    also deletes those reviews.
    """
    # Check business exists.
    business_key = client.key(BUSINESSES, business_id)
    business = client.get(key=business_key)
    if business is None:
        return ERROR_BUSINESS_NOT_FOUND, 404

    client.delete(business_key)
    return '', 204

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

