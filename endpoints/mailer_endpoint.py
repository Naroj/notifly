from flask import Flask, request, jsonify, Response
import smtplib
from email.mime.text import MIMEText
example = Flask(__name__)

"""
REST endpoint which receives zone input and emails it to someone of great importance
"""

def send_mail(from_email, to_email, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    s = smtplib.SMTP('localhost')
    s.send_message(msg)
    s.quit()

@example.route('/', methods=['PUT'])
def accept_notification():
    content = request.data
    """
    pass content on to your unicorn army
    """
    email = {
        'from_email' : request.headers.get('from_email'),
        'to_email' : request.headers.get('to_email'),
        'subject' : request.headers.get('subject'),
        'body' : str(content)
    }
    try:
        send_mail(**email)
    except:
        return jsonify({'msg' : 'smtp says no!'})
    return jsonify({'msg' : 'gracias amigo!'})

if __name__ == '__main__':
    example.run(host='127.0.0.1', port=1025)
