from flask import Blueprint, request, current_app, render_template, redirect, url_for, flash, make_response, jsonify
from db.db_connector import DBConnector
import json
import requests
from api.auth.jwt_utils import validate_token

admin = Blueprint('admin', __name__, template_folder='templates')

########################################################
###             Admin Portal endpoints               ###
########################################################

@admin.route('/ap/login', methods=['GET', 'POST'])
def login():
    print(f'Login functoion!')
    print(f'Request data: {request.get_data()}')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        login_url = f'http://127.0.0.1:5000/login'
        login_payload = {'username': username, 'password': password}
        login_response = requests.post(login_url, json=login_payload)
        data = login_response.json()
        print(f'Login response status code: {login_response.status_code}')
        print(f'Login data: {data}')
        token = data['token']
        is_valid, payload = validate_token(token)
        is_agent = payload.get('is_agent')
        if login_response.status_code != 200:
            return jsonify({'status': "Unauthorized"}), 403
        if not is_agent:
            return jsonify({'status': "Unauthorized"}), 403
        response = redirect(url_for('admin.view_tickets'))
        response.set_cookie('session_token', f'{token}')
        response.set_cookie('username', username)
        return response
    return render_template('login.html')

@admin.route('/ap/logout')
def logout():
    response = make_response(redirect(url_for('admin.login')))
    response.set_cookie('token', '', expires=0)
    return response

@admin.route('/ap/tickets')
def view_tickets():
    dbc = DBConnector()
    token = request.cookies.get('session_token')
    is_valid, payload = validate_token(token)
    if not is_valid:
        return jsonify({'status': "Unauthorized"}), 403
    try:
        if not payload.get('is_agent'):
            return jsonify({'status': "Unauthorized"}), 403
        tickets = dbc.execute_query('get_agent_tickets')
        return render_template('tickets.html', tickets=tickets)
    except KeyError:
        return jsonify({'status': "Unauthorized"}), 403

@admin.route('/ap/ticket/<int:ticket_id>', methods=['GET', 'POST'])
def ticket_detail(ticket_id):
    dbc = DBConnector()
    token = request.cookies.get('session_token')
    is_valid, payload = validate_token(token)
    if not is_valid or not payload.get('is_agent'):
        return jsonify({'status': "Unauthorized"}), 403
    # Get the ticket details
    result = dbc.execute_query('get_ticket_by_id', args=ticket_id)
    user_id = result['UserID']
    is_agent = dbc.execute_query('get_user_agent', args=user_id)
    result['Messages'] = json.loads(result['Messages'])

    if result['UserID'] != user_id and not is_agent:
        error_message = "You are not authorized to view this ticket."
        return render_template('ticket_detail.html', ticket=None, error_message=error_message), 403

    success_message = None
    if request.method == 'POST':
        new_status = request.form['status']
        updated = dbc.execute_query('update_ticket_status', args={'ticket_id':ticket_id, 'status':new_status})
        if updated:
            success_message = "Ticket status updated successfully"
        else:
            error_message = "Unkown error. Sorry we will look into it "
            return render_template('ticket_detail.html', ticket=None, error_message=error_message), 403
        success_message = "Ticket status updated successfully"
    return render_template('ticket_detail.html', ticket=result, success_message=success_message)

@admin.route("/ap/ticket/<int:ticket_id>/new-message", methods=['POST'])
def new_agent_message(ticket_id):
    dbc = DBConnector()
    ## Check if request comes from trusted connection
    token = request.cookies.get('session_token')
    is_valid, payload = validate_token(token)
    if not is_valid or not payload.get('is_agent'):
        return jsonify({'status': "Unauthorized"}), 403
    cookies = request.cookies
    message = request.form['message']
    result = dbc.execute_query('update_ticket_messages', args={
        "username": cookies['username'],
        "ticket_id": ticket_id,
        "message": message,
        'is_agent': True
    })
    success_message = None
    result = dbc.execute_query('get_ticket_by_id', args=ticket_id)
    if result.get('Messages'):
        result['Messages'] = json.loads(result['Messages'])
    return redirect(url_for('admin.ticket_detail', ticket_id=ticket_id))

########################################################
###             User support endpoints               ###
########################################################

@admin.route('/support/new-ticket', methods=['POST'])
def new_ticket():
    dbc = DBConnector()
    dict_data = request.get_json()
    print('\n')
    print(dict_data)
    token = dict_data['token']
    is_valid, payload = validate_token(token)
    if not is_valid:
        return jsonify({'status': "Unauthorized"}), 403
    if dict_data['category'] not in ['Technical Issue', 'Billing', 'Question', 'Feature Request']:
        return jsonify({'status': "Bad request"}), 400
    ticket = {
        'user_id': dict_data['user_id'],
        'category': dict_data['category'],
        'status': dict_data['status'],
        'description': dict_data['description'],
        'messages': json.dumps([])
    }
    result = dbc.execute_query('create_ticket', args=ticket)
    if isinstance(result, int):
        return jsonify({'status': 'Ok', 'ticket_id':result}), 200
    else:
        return jsonify({'status': 'Bad reuest'}), 400

@admin.route('/support/tickets', methods=['POST'])
def tickets():
    dbc = DBConnector()
    dict_data = request.get_json()
    results = None
    token = dict_data['token']
    is_valid, payload = validate_token(token)
    if not is_valid or payload.get('is_agent'):
        return jsonify({'status': 'Unauthorized'}), 403
    if not payload.get('is_admin'):
        results = dbc.execute_query('get_user_tickets', args=dict_data['user_id'])
    if payload.get('is_admin'):
        results = dbc.execute_query('get_admin_tickets', args=dict_data['company_id'])
    if isinstance(results, list):
        return jsonify({'status': 'Ok', 'tickets': results}), 200
    return jsonify({'status': 'Bad request'}), 400

@admin.route('/support/ticket/<int:ticket_id>', methods=['GET', 'POST'])
def user_ticket_detail(ticket_id):
    dbc = DBConnector()
    # Get the ticket details
    result = dbc.execute_query('get_ticket_by_id', args=ticket_id)
    user_id = result['UserID']
    is_agent = dbc.execute_query('get_user_agent', args=user_id)
    result['Messages'] = json.loads(result['Messages'])

    if result['UserID'] != user_id and not is_agent:
        return jsonify({'status': 'Unauthorized'}), 403
    return jsonify({'status': 'Ok', 'ticket': result}), 200

@admin.route("/support/ticket/<int:ticket_id>/new-message", methods=['POST'])
def new_message(ticket_id):
    dbc = DBConnector()
    dict_data = request.get_json()
    print(dict_data)
    result = dbc.execute_query('get_ticket_by_id', args=ticket_id)
    is_agent = False
    if int(result['UserID']) != int(dict_data['user_id']):
        is_agent = dbc.execute_query('get_user_agent', args=dict_data['user_id'])
        if not is_agent:
            if dict_data['token'] != current_app.config['ADMIN_AUTH_TOKEN']:
                return jsonify({'status': "Unauthorized"}), 403
    user = dbc.execute_query('get_user_by_id', args=dict_data['user_id'])
    result = dbc.execute_query('update_ticket_messages', args={
        "username": user['Username'],
        "ticket_id": ticket_id,
        "message": dict_data['message'],
        'is_agent': is_agent
    })
    if result:
        return jsonify({'status': 'Ok'}), 200
    else:
        return jsonify({'status': 'Bad request'}), 400
