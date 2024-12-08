import os
import json
import keyring
import datetime
import webbrowser
import requests
from flask import Flask, request, redirect

KEYRING_APPNAME = 'IVAOOAuth2FlowTester'
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:41234/auth/callback'
SCOPE = 'profile email discord location birthday'
IVAO_VID = 540147

OPENID_CONFIG_URL = 'https://api.ivao.aero/.well-known/openid-configuration'

def fetch_openid_config():
    response = requests.get(OPENID_CONFIG_URL)
    response.raise_for_status() 
    return response.json()

openid_config = fetch_openid_config()
AUTHORIZATION_URL = openid_config['authorization_endpoint']
TOKEN_URL = openid_config['token_endpoint']
USERINFO_URL = openid_config['userinfo_endpoint']

app = Flask(__name__)

@app.route('/')
def index():
    keyring_data = get_keyring_data(str(IVAO_VID))
    if not keyring_data:
        print("Error: No stored keyring data for the VID.")
        return redirect('/auth')

    try:
        access_token = get_access_token(keyring_data)
        user_info = fetch_user_info(access_token)
        print("Auth data successfully retrieved.")
        return user_info
    except Exception as ex:
        return str(ex), 400

@app.route('/auth')
def auth():
    auth_url = (
        f"{AUTHORIZATION_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={SCOPE}"
    )
    return redirect(auth_url)

@app.route('/auth/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Error: No authorization code provided", 400

    try:
        tokens = exchange_auth_code_for_tokens(code)
        save_keyring_data(tokens)
        return "Auth data successfully saved to keyring."
    except Exception as ex:
        return str(ex), 400

def exchange_auth_code_for_tokens(auth_code: str) -> dict[str, object]:
    token_data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
    }
    response = requests.post(TOKEN_URL, data=token_data)
    response.raise_for_status()
    return process_token_response(response)

def refresh_access_token(refresh_token: str) -> dict[str, object]:
    token_data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    response = requests.post(TOKEN_URL, data=token_data)
    response.raise_for_status()
    return process_token_response(response)

def get_access_token(keyring_data: dict[str, object]) -> str:
    expires_at = datetime.datetime.fromisoformat(keyring_data['expires_at'])
    if expires_at < datetime.datetime.now():
        print("Access token expired, refreshing...")
        tokens = refresh_access_token(keyring_data['refresh_token'])
        save_keyring_data(tokens)
        print("New auth data saved to keyring.")
        return tokens['access_token']
    
    print("Using valid access token.")
    return keyring_data['access_token']

def fetch_user_info(access_token: str) -> dict[str, object]:
    response = requests.get(USERINFO_URL, headers={'Authorization': f'Bearer {access_token}'})
    response.raise_for_status()
    return response.json()

def process_token_response(response: requests.Response) -> dict[str, object]:
    token_data = response.json()
    if 'access_token' not in token_data:
        raise Exception("Error: Access token not received.")
    
    expires_at = datetime.datetime.now() + datetime.timedelta(seconds=token_data.get('expires_in', 1200))
    return {
        'vid': fetch_user_info(token_data['access_token']).get('id'),
        'access_token': token_data['access_token'],
        'refresh_token': token_data['refresh_token'],
        'expires_at': expires_at.isoformat(),
        'updated_at': datetime.datetime.now().isoformat(),
    }

def get_keyring_data(vid: str) -> dict[str, object]:
    data = keyring.get_password(KEYRING_APPNAME, vid)
    return json.loads(data) if data else {}

def save_keyring_data(data: dict[str, object]):
    keyring.set_password(KEYRING_APPNAME, str(data['vid']), json.dumps(data))

def start_server():
    webbrowser.open('http://localhost:41234')
    app.run(debug=True, port=41234)

if __name__ == '__main__':
    start_server()
