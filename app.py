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
REDIRECT_URI = 'http://localhost:51234/auth/callback'
SCOPE = 'openid profile email discord location'

OPENID_CONFIG_URL = 'https://api.ivao.aero/.well-known/openid-configuration'

def get_openid_configuration():
  response = requests.get(OPENID_CONFIG_URL)
  if response.status_code == 200:
    return response.json()
  else:
    raise Exception(f"Error fetching OpenID configuration: {response.status_code}")

openid_config = get_openid_configuration()
AUTHORIZATION_URL = openid_config['authorization_endpoint']
TOKEN_URL = openid_config['token_endpoint']
USERINFO_URL = openid_config['userinfo_endpoint']

app = Flask(__name__)

@app.route('/')
def index():
  ivao_vid = '540147'
  keyring_data = json.loads(keyring.get_password(KEYRING_APPNAME, ivao_vid) or '{}')
  if not keyring_data:
    # We don't have any keyring data associated to the VID in the envfile
    print("Error: We don't have any keyring data associated to the VID in the envfile")
    return redirect('/auth')
  
  if datetime.datetime.fromisoformat(keyring_data.get('expiresAt')) < datetime.datetime.now():
    # access token expired
    print("Error: Access token expired, refresh logic has not yet been implemented")
    return "Error: Access token expired, refresh logic has not yet been implemented", 400
  
  response = requests.get(USERINFO_URL, headers={'Authorization': f'Bearer {keyring_data.get('accessToken')}'})
  if response.status_code != 200:
    return f"Error getting user info: {response.status_code}", 400
  
  print("Auth data successfully obtained from the keyring")
  user_info = response.json()
  return user_info


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
    return "Error: No code provided", 400

  token_data = {
    'code': code,
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'redirect_uri': REDIRECT_URI,
    'grant_type': 'authorization_code',
  }
  response = requests.post(TOKEN_URL, data=token_data)

  if response.status_code != 200:
    return f"Error getting tokens: {response.status_code}", 400

  token_info = response.json()
  access_token = token_info.get('access_token')
  if not access_token:
    return "Error: No access token received", 400
  
  response = requests.get(USERINFO_URL, headers={'Authorization': f'Bearer {access_token}'})
  if response.status_code != 200:
    return f"Error getting user info: {response.status_code}", 400
  
  user_info = response.json()
  ivao_vid = user_info.get('id')
  if not ivao_vid:
    return f"Error: No IVAO VID received", 400
  
  keyring_data = {
    'vid': ivao_vid,
    'accessToken': access_token,
    'expiresAt': (datetime.datetime.now() + datetime.timedelta(seconds=int(token_info.get('expires_in', 1200)))).isoformat(),
    'refreshToken': token_info.get('refresh_token'),
    'updatedAt': datetime.datetime.now().isoformat(),
    'version': 1
  }
  keyring.set_password(KEYRING_APPNAME, str(ivao_vid), json.dumps(keyring_data))
  return "Auth data has been saved to keyring"

def start_server():
  webbrowser.open('http://localhost:51234')
  app.run(debug=True, port=51234)

if __name__ == '__main__':
  start_server()
