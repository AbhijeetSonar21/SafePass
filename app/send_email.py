import smtplib
import sys

def send_email(to, subject, body):
    # Replace these with your own email and password
    email = 'abhijeetsonar21@gmail.com'
    password = 'lrwl otwk haup ojoz'

    message = f'Subject: {subject}\n\n{body}'

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(email, password)
    server.sendmail(email, to, message)
    server.quit()

if __name__ == '__main__':
    to = sys.argv[1]
    subject = sys.argv[2]
    body = sys.argv[3]
    send_email(to, subject, body)
