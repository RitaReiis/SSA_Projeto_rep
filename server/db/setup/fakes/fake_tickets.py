import json

data = [
    {
        "UserID": 1,
        "Status": "Waiting for customer",
        "Category": "Technical Issue",
        "Description": "Having trouble with login credentials.",
        "Messages": json.dumps([
            {"Username": "jdoe", "MessageText": "I can't open the CashFlow tab, I keep getting an error."},
            {"Username": "alice@isctespot", "MessageText": "Please logout and clean the cache of your browser and try again."}
        ]),
        "CreatedAt": "2024-08-29 18:10:45",
        "UpdatedAt": "2024-08-29 18:15:27"
    },
    {
        "UserID": 2,
        "Status": "In Progress",
        "Category": "Billing",
        "Description": "Incorrect amount charged on last invoice.",
        "Messages": json.dumps([
            {"Username": "asmith", "MessageText": "I think I've been overcharged on my last bill."},
            {"Username": "adam@isctespot", "MessageText": "We are investigating the issue, please hold tight."}
        ]),
        "CreatedAt": "2024-09-09 18:10:45",
        "UpdatedAt": "2024-09-11 18:15:27"
    },
    {
        "UserID": 3,
        "Status": "Resolved",
        "Category": "Question",
        "Description": "AI features?",
        "Messages": json.dumps([
            {"Username": "bwilliams", "MessageText": "Are you planning to have AI to evaluate the performance of employees?."},
            {"Username": "adam@isctespot", "MessageText": "Hello bwilliams, yes we are planning to release AI features in 2025Q2. You can check more details here (url)"}
        ]),
        "CreatedAt": "2024-09-01 11:10:15",
        "UpdatedAt": "2024-09-02 11:12:25"
    },
]
