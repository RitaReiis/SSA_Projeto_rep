from flask import Blueprint, request, jsonify
from db.db_connector import DBConnector
from api.auth.jwt_utils import validate_token

clients = Blueprint('clients', __name__)

@clients.route('/clients', methods=['GET', 'POST'])
def list_clients():
    ''' List clients function'''
    dbc = DBConnector()
    dict_data = request.get_json()
    token = dict_data['token']
    is_valid, payload = validate_token(token)
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorised'}), 403
    comp_id = dbc.execute_query(query='get_compnay_id_by_user', args=payload['user_id'])
    results = dbc.execute_query(query='get_clients_list', args=comp_id)
    if isinstance(results, list):
        return jsonify({'status': 'Ok', 'clients': results}), 200
    return jsonify({'status': 'Bad credentials'}), 403

@clients.route('/clients/new', methods=['POST'])
def new_client():
    ''' Create a new client '''
    dbc = DBConnector()
    dict_data = request.get_json()
    token = dict_data['token']
    is_valid, payload = validate_token(token)
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403
    comp_id = payload['comp_id']
    result = dbc.execute_query('create_client', args={
        'comp_id': comp_id,
        'first_name': dict_data['first_name'],
        'last_name': dict_data['last_name'],
        'email': dict_data['email'],
        'phone_number': dict_data['phone_number'],
        'address': dict_data['address'],
        'city': dict_data['city'],
        'country': dict_data['country'],
    })
    if isinstance(result, int):
        return jsonify({'status': 'Ok', 'client_id':result}), 200
    else:
        return jsonify({'status': 'Bad reuest'}), 400

@clients.route('/clients/delete', methods=['POST'])
def delete_client():
    ''' Delete client '''
    dbc = DBConnector()
    dict_data = request.get_json()
    token = dict_data['token']
    is_valid, payload = validate_token(token)
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403
    result = dbc.execute_query(query='delete_client_by_id', args=dict_data['client_id'])
    if isinstance(result, int):
        return jsonify({'status': 'Ok', 'client_id':result}), 200
    else:
        return jsonify({'status': 'Bad reuest'}), 400
 