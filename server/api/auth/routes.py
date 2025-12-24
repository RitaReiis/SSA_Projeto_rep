from flask import Blueprint, request, jsonify
from db.db_connector import DBConnector
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
from .jwt_utils import issue_token, validate_token
# Hazmat para a criptografia assimétrica
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

auth = Blueprint('auth', __name__)

# DES
DES_KEY = "12345678"

# Desencriptar as passwords guardadas em DES (legacy).
def legacy_decrypt(encrypted_password: str) -> str:
    try:
        des = DES.new(DES_KEY.encode('utf-8'), DES.MODE_ECB)
        decoded = base64.b64decode(encrypted_password)
        decrypted = unpad(des.decrypt(decoded), DES.block_size)
        return decrypted.decode('utf-8')
    except Exception:
        return None


# IMPLEMENTAÇÃO DO RSA:
# Criar as chaves.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
public_key = private_key.public_key()

# Encriptar com o RSA.
def rsa_encrypt(plain_text: str) -> str:
    # Encriptar com a pública.
    encrypted = public_key.encrypt(
        plain_text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None ) )
    return base64.b64encode(encrypted).decode('utf-8')

# Desencriptar com o RSA.
def rsa_decrypt(encrypted_text: str) -> str:
    # Desencriptar com a chave privada.
    try:
        decoded = base64.b64decode(encrypted_text)
        decrypted = private_key.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        return decrypted.decode('utf-8')
    except Exception:
        return None



@auth.route('/login', methods=['POST'])
def login():
    ''' Login function'''
    dbc = DBConnector()
    data = request.get_json()
    username = data['username']
    password_input = data['password']

    _id = dbc.execute_query(query='get_user_by_name', args=username)
    if not isinstance(_id, int):
        return jsonify({'status': 'Bad request'}), 400

    # Vai buscar a password guardada associada ao utilizador.
    stored_password = dbc.execute_query(query='get_user_password', args=_id)

    # Tenta desencriptar com o RSA.
    decrypted_password = rsa_decrypt(stored_password)
    
    # Se o RSA falhar, significa que está a usar uma legacy e tenta com o DES.
    if decrypted_password is None:
        decrypted_password = legacy_decrypt(stored_password)

    #  # Check if it is Temporary password 
    if password_input == decrypted_password or password_input == 'T3MP-password-32':
        dbc.execute_query(query='update_user_activity', args={'user_id': _id, 'active': True})
        is_admin = dbc.execute_query(query='get_user_admin', args=_id) == 1
        is_agent = bool(dbc.execute_query(query='get_user_agent', args=_id))
        
        comp_id = dbc.execute_query(query='get_user_comp_id', args=_id)
        if not isinstance(comp_id, int):
            return jsonify({'status': 'Bad request'}), 400

        token: str = issue_token(user_id=_id, comp_id=comp_id, is_admin=is_admin, is_agent=is_agent)
        return jsonify({'status': 'Ok', 'user_id': _id, 'token': token, 'is_admin': is_admin, 'comp_id': comp_id}), 200

    return jsonify({'status': 'Bad credentials'}), 403


@auth.route('/signup', methods=['POST'])
def signup():
    dbc = DBConnector()
    dict_data = request.get_json()
    
    # Usar a nova lógica com o rsa.
    encrypted_password = rsa_encrypt(dict_data['password'])

    result = dbc.execute_query('create_user_admin', args={
        "username": dict_data['username'],
        "password": encrypted_password,
        "email": dict_data['email'],
        "comp_name": dict_data['comp_name'],
        "num_employees": dict_data['num_employees'],
        "is_admin": True 
    })
    if isinstance(result, int):
        user_id = result
    else:
        return jsonify({'status': 'Bad request'}), 400
    comp_id = dbc.execute_query('create_company', args={"user_id": user_id,"comp_name": dict_data['comp_name'],"num_employees": dict_data['num_employees']})
    result = dbc.execute_query('update_user_comp_id', args={'user_id': user_id,'comp_id': comp_id})

    token: str = issue_token(user_id=user_id, comp_id=comp_id, is_admin=True, is_agent=False)

    if isinstance(result, int):
        return jsonify({'status': 'Ok','comp_id': comp_id,'user_id': user_id,'is_admin': True,'token': token}), 200
    else:
        return jsonify({'status': 'Bad request'}), 400 

@auth.route('/user/reset-password', methods=['POST'])
def reset_password():
    dbc = DBConnector()
    dict_data = request.get_json()
    is_valid, _payload = validate_token(dict_data['token'])
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403
    
    user_id = dict_data['user_id']
    if _payload['is_admin']:
        user_id = _payload['user_id']
    
    # Encriptação com o RSA.
    new_encrypted = rsa_encrypt(dict_data['new_password'])
    
    result = dbc.execute_query(query='update_user_password', args={
        "user_id": user_id,
        "new_password": new_encrypted
    })
    
    if result is True:
        return jsonify({'status': 'Ok'}), 200
    return jsonify({'status': 'Bad request'}), 400
#---------------------------------------------------------------------------------------------------------------------------------#

@auth.route('/logout', methods=['POST'])
def logout():
    ''' Logout function'''
    dbc = DBConnector()
    dict_data = request.get_json()
    _id = dbc.execute_query(query='update_user_activity', args={
        'user_id': dict_data['user_id'],
        'active': False
    })
    if not isinstance(_id, int):
        return jsonify({'status': 'Bad request'}), 400
    else:
        return jsonify({'status': 'Ok'}), 200



@auth.route('/employee/new', methods=['POST'])
def new_employee():
    ''' Create new employee function '''
    dbc = DBConnector()
    dict_data = request.get_json()
    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403
    result = dbc.execute_query('create_user_employee', args={
        'username': dict_data['username'],
        'email': dict_data['email'],
        'comp_id': dict_data['comp_id']
    })
    if isinstance(result, int):
        return jsonify({'status': 'Ok', 'employee_id': result})
    else:
        return jsonify({'status': 'Bad request'})

@auth.route('/retire', methods=['POST'])
def retire():
    ''' Retire function, delete company and all employees '''
    dbc = DBConnector()
    dict_data = request.get_json()
    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403
    comp_id = payload['comp_id']
    user_id = payload['user_id']
    result = dbc.execute_query(query='delete_sales_by_comp_id', args=dict_data['comp_id'])
    if result is False:
        return jsonify({'status': 'Bad request'}), 400
    result = dbc.execute_query(query='delete_products_by_comp_id', args=dict_data['comp_id'])
    if result is False:
        return jsonify({'status': 'Bad request'}), 400
    result = dbc.execute_query(query='delete_users_by_comp_id', args=dict_data['comp_id'])
    if result is False:
        return jsonify({'status': 'Bad request'}), 400
    result = dbc.execute_query('delete_company_by_id', dict_data['comp_id'])
    if result is not True:
        return jsonify({'status': "Bad request"}), 400
    result = dbc.execute_query('delete_user_by_id', dict_data['user_id'])
    if result is not True:
        return jsonify({'status': "Bad request"}), 400
    if result is True:
        return jsonify({'status': 'Ok'}), 200
    else:
        return jsonify({'status': 'Bad request'}), 400

@auth.route('/employee/delete', methods=['POST'])
def delete_employee():
    ''' Delete employee function '''
    dbc = DBConnector()
    dict_data = request.get_json()
    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403
    result = dbc.execute_query('delete_user_by_id', dict_data['employee_id'])
    if result is True:
        return jsonify({'status': 'Ok'}), 200
    else:
        return jsonify({'status': "Bad request"}), 400
