from smtplib import SMTP

s = SMTP("127.0.0.1", "8025")
s.ehlo()
s.login("test", "1234")
s.putcmd("ls")
s.quit()