import smtplib
from email.message import EmailMessage

def send_email(config, to_address, subject, text_body):
    host=config.get("SMTP_HOST","")
    if not host:
        return {"delivered":False,"mode":"outbox","reason":"SMTP not configured"}
    msg=EmailMessage()
    msg["Subject"]=subject
    msg["From"]=config.get("EMAIL_FROM","SentinelScope <no-reply@localhost>")
    msg["To"]=to_address
    msg.set_content(text_body)
    with smtplib.SMTP(host,int(config.get("SMTP_PORT",587)),timeout=15) as smtp:
        if config.get("SMTP_USE_TLS",True): smtp.starttls()
        user=config.get("SMTP_USERNAME","")
        if user: smtp.login(user,config.get("SMTP_PASSWORD",""))
        smtp.send_message(msg)
    return {"delivered":True,"mode":"smtp"}
