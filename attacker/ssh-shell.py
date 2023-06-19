import paramiko
import time

# prompt user for username and password
username = 'clara'
password = 'cFilia'

# set up SSH client
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# connect to remote machine
ssh.connect('172.21.0.6', username=username, password=password)

# start an interactive shell session
shell = ssh.invoke_shell()

# wait for the shell to be ready
#time.sleep(1)
#shell.send(username + '\n')

# wait for the shell to prompt for the password
#time.sleep(1)
#shell.send(password + '\n')

# send a command to the shell
shell.send('whoami\n')

# wait for the command output
time.sleep(1)

# print the command output
output = shell.recv(1024).decode()
print(output)

# sleep for 2 minutes
time.sleep(600)

# close the shell session
shell.close()
# close SSH connection
ssh.close()