import requests
import sys
import os

base_url = 'http://127.0.0.1:5000'

def test_output_status(status, text):
    if status == 'pass':
        print(f'\033[92m[PASS]\033[0m {text}')
    elif status == 'info':
        print(f'\033[96m[INFO]\033[0m {text}')
    else:
        print(f'\033[91m[FAIL]\033[0m {text}')
        sys.exit(1)

# User login
test_output_status('info', 'Testing User authentication')
login_url = f'{base_url}/login'
login_payload = {'username': 'jdoe', 'password': 'password123'}
login_response = requests.post(login_url, json=login_payload)
login_data = login_response.json()
token = login_data['token']
user_id = 0
if login_data['status'] == 'Ok':
    test_output_status('pass', 'Login successful')
    user_id = login_data['user_id']
else:
    test_output_status('fail', 'Failed to Login user')

# Admin login
test_output_status('info', 'Testing Agent authentication')
agent_login_url = f'{base_url}/login'
agent_login_payload = {'username': 'adam@isctespot', 'password': 'password123'}
agent_login_response = requests.post(agent_login_url, json=agent_login_payload)
agent_login_data = agent_login_response.json()
agent_token = agent_login_data['token']
if agent_login_data['status'] == 'Ok':
    test_output_status('pass', 'Agent login successful')
else:
    test_output_status('fail', 'Failed to Agent login')

# Company Admin gets support tickets
test_output_status('info', 'Testing User getting support tickets')
get_support_tickets_url = f'{base_url}/support/tickets'
get_support_tickets_payload = {
    'user_id': user_id,
    'company_id': 1,
    'token': token,
}
get_support_tickets_response = requests.post(get_support_tickets_url, json=get_support_tickets_payload)
get_support_tickets_data = get_support_tickets_response.json()
if get_support_tickets_data['status'] == 'Ok':
    test_output_status('pass', 'Get company admin tickets successful')
else:
    test_output_status('fail', 'Failed to get company admin tickets')

# Company User gets support tickets (returns empty list)
test_output_status('info', 'Testing User getting support tickets')
get_support_tickets_url = f'{base_url}/support/tickets'
get_support_tickets_payload = {
    'user_id': 2,  
    'company_id': 1, # asmith
    'token': token,
}
get_support_tickets_response = requests.post(get_support_tickets_url, json=get_support_tickets_payload)
get_support_tickets_data = get_support_tickets_response.json()
if get_support_tickets_data['status'] == 'Ok' and get_support_tickets_data['tickets']:
    test_output_status('pass', 'Get user tickets successful')
else:
    test_output_status('fail', 'Failed to get user tickets')

# User creates a new ticket
test_output_status('info', 'Testing User creating a new ticket')
new_ticket_url = f'{base_url}/support/new-ticket'
new_ticket_payload = {
    'user_id': 2,       # asmith
    'token': token,
    'category': 'Question',
    'status': 'Waiting for Support',
    'description': 'This is a test'
}
new_ticket_response = requests.post(new_ticket_url, json=new_ticket_payload)
new_ticket_data = new_ticket_response.json()
ticket_id = 0
if new_ticket_data['status'] == 'Ok':
    ticket_id = new_ticket_data['ticket_id']
    test_output_status('pass', 'Create ticket successful')
else:
    test_output_status('fail', 'Failed to create ticket')

# User opens a ticket
test_output_status('info', 'Testing Get ticket by id')
get_ticket_url = f'{base_url}/support/ticket/{ticket_id}'
get_ticket_payload = {
    'user_id': 2,
}
get_ticket_response = requests.post(get_ticket_url, json=get_ticket_payload)
get_ticket_data = get_ticket_response.json()
if get_ticket_data['status'] == 'Ok':
    test_output_status('pass', 'Get ticket by id successful')
else:
    test_output_status('fail', 'Failed to get ticket by id')

# User makes a comment on the ticket
test_output_status('info', 'Testing new comment on ticket')
new_message_url = f'{base_url}/support/ticket/{ticket_id}/new-message'
new_message_payload = {
    'user_id': 2,
    'message': 'This is a test message from user'
}
new_message_response = requests.post(new_message_url, json=new_message_payload)
new_message_data = new_message_response.json()
if new_message_data['status'] == 'Ok':
    test_output_status('pass', 'New comment successful')
else:
    test_output_status('fail', 'Failed to insert new coment')

# Agent also comments on the ticket
test_output_status('info', 'Testing Agent comment on ticket')
agent_message_url = f'{base_url}/support/ticket/{ticket_id}/new-message'
agent_message_payload = {
    'user_id': 17,
    'message': 'This is a test message from agent',
    'token': agent_token
}
agent_message_response = requests.post(agent_message_url, json=agent_message_payload)
agent_message_data = agent_message_response.json()
if agent_message_data['status'] == 'Ok':
    test_output_status('pass', 'New comment successful')
else:
    test_output_status('fail', 'Failed to insert new coment')
