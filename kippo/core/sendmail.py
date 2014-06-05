import smtplib
from email.mime.text import MIMEText
from kippo.core.config import config

def sendEmail(subject,  message):
    cfg = config()

    msg = MIMEText(message)
    msg['Subject'] = subject

    toEmail = cfg.get('smtp', 'email_to')
    msg['To'] = toEmail

    fromEmail = cfg.get('smtp', 'email_from')
    msg['From'] = fromEmail

    smtpHost = cfg.get('smtp', 'smtp_host')
    smtpPort = cfg.get('smtp', 'smtp_port')
    smtpUsername = cfg.get('smtp', 'smtp_username')
    smtpPassword = cfg.get('smtp', 'smtp_Password')
    smtpEnc = cfg.get('smtp', 'smtp_enc')

    s = smtplib.SMTP(smtpHost, smtpPort)
    if smtpEnc == 'ssl':
        s = smtplib.SMTP_SSL(smtpHost, smtpPort)
    elif smtpEnc == 'tls':
        s.starttls()
    s.login(smtpUsername, smtpPassword)
    s.sendmail(fromEmail, [toEmail], msg.as_string())
    s.quit()
