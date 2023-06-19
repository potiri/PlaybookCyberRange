import paramiko
#import time

host = "172.21.0.6"
username = "clara"
password = "cFilia"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#ssh.connect(host, username=username, password=password)

ssh.connect(host, username="clara", password="cFilia", look_for_keys=False, allow_agent=False, timeout=5, banner_timeout=10, auth_timeout=5, get_pty=True)
    
ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("mkdir test3")
#time.sleep(120)

#ssh.close()