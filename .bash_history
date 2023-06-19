hydra -l connor -p sergeant 172.17.0.2 -s 8080 http-get /
docker stop http-web-server
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
cd docker_http
docker build -t http-server .
docker run -dit --name http-web-server -p 8080:80 http-server
docker ps -a
docker inspect [bfa13638f714] | grep-A 5LogConfig
docker inspect bfa13638f714 | grep-A 5LogConfig
docker system info | grep -i log
sudo docker inspect bfa13638f714 | grep-A 5LogConfig
docker inspect -f '{{.HostConfig.LogConfig.Type}}' 200~bfa13638f714
docker inspect -f '{{.HostConfig.LogConfig.Type}}' bfa13638f714
cd /var/docker
cd /var/docker/
cd
cd /var/docker/
cd var/docker/
cd /var
dir
cd log
dir
cd docker
dir
cat /etc/docker/daemon.json
cat /etc/rsyslog.d/
cd /etc/rsyslog.d/
dir
cat wazuh-docker-conf
cat wazuh-docker.conf
docker ps -a
docker start http-web-server 
docker ps -a
docker ps -a
docker system info | grep -i log
cd /var/lib/docker/containers/
dir
cd /var/log/
dir
cd docker
dir
ls
cd
cd /etc/rsyslog.d/
dir
cat wazuh-docker.conf
systemctl restart rsyslog
cd
cd docker_http
dir
docker run -dit --name my-running-app -p 9090:90 http-server
cd /var/log/
cd docker
dir
docker ps -a
docker stop my-running-app
docker rm my-running-app 
docker ps -a
dir
sudo rsyslogd -f /etc/rsyslog.d/wazuh-docker.conf -N1
systemctl restart rsyslog
dir
ls
cd /var/log
dir
ls /var/log/docker/http1.log
docker ps -a
cd docker_http
docker run -dit --name http1 -p 9090:90 http-server
docker system info | grep -i log
docker ps -a
sudo grep -r "5da32415852b\[.*]" /var/log
sudo journalctl -u docker.service | grep "5da32415852b\[.*]"
docker logs http-web-server
cat /etc/docker/daemon.json
systemctl restart docker
cd
systemctl restart docker
docker ps -a
systemctl start docker
systemctl status docker.service
dockerd
sudo dockerd --debug
rm /var/run/docker.pid
dockerd
sudo systemctl stop docker
sudo dockerd
systemctl start docker
docker ps -a
sudo service --status-all
sudo service docker start
docker system info | grep -i log
docker ps -a
sudo systemctl start docker
systemctl status docker.service
sudo dockerd --debug
ps axf | grep docker | grep -v grep | awk '{print "kill -9 " $1}' | sudo sh 
sudo systemctl start docker
docker ps -a
cd /var/logs
cd /var/log/
dir
cd docker
dir
cd /var/lib/docker/containers/
dir
cd  bfa13638f7144e8c121e2b11fdf1dfc588a923ab677cac73a184ec1576d3e339
di
dir
cat container-cached.log 
docker ps -a
curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='192.168.2.181' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
jupyter notebook --no-browser --port=8090 --allow-root
docker-compose --version
curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version
docker-compose
git clone https://github.com/wazuh/wazuh-docker.git -b v4.3.10
cd single-node
dir
cd wazuh-docker
dir
cd single-node
dir
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install gnupg apt-transport-https

clear
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
WAZUH_MANAGER="192.168.2.181" apt-get install wazuh-agent
apt-get install wazuh-agent
cd /var/ossec/etc/
dir
cat ossec.cof
cat ossec.conf
cd
curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='192.168.2.181' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
dir
cd wazuh-agent-4.3.10.deb
cat wazuh-agent-4.3.10.deb
dir
rm wazuh-agent-4.3.10.deb
dir
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
cd /etc/apt/sources.list.d
dir
cat wazuh.list
rm wazuh.list
dir
cd
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
docker ps -a
WAZUH_MANAGER="192.168.2.181" install wazuh-agent
WAZUH_MANAGER="192.168.2.181" apt-get install wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
WAZUH_MANAGER="172.21.0.3" apt-get install wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
jupyter notebook --no-browser --port=8090 --allow-root
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
cd /var/ossec/var/run/
dir
cd /var/log
dir
cd docker
dir
docker pull tomcat
docker run -d -P --name tomcat_hello tomcat
docker exec -it tomcat_hello ps
docker exec -it tomcat_hello sh -c "echo test"
docker exec -it tomcat_hello /bin/bash
docker stop tomcat_hello
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
pip install docker
cd /var/lib/docker/containers/
dir
cd bfa13638f7144e8c121e2b11fdf1dfc588a923ab677cac73a184ec1576d3e339/
dir
cd
docker logs http-web-server
docker ps -a
cd /var/ossec/var/run
dir
cat wazuh-agentd.state
apt-get remove wazuh-agent
apt-get remove --purge wazuh-agent
systemctl disable wazuh-agent
systemctl daemon-reload
clear
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
cd
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER="172.21.0.3" apt-get install wazuh-agent
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
cd /var/ossec/var/run
dir
cd /var/ossec/var
dir
cd run
dir
cd
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
cd /var/ossec/var
dir
cd run
dir
cat wazuh-agentd.state
cd
vi /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
systemctl status wazuh-agent
systemctl restart wazuh-agent
systemctl status wazuh-agent
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
ssh admin@172.17.0.3
ssh connor@172.17.0.2
docker ps -a
docker rm http1
docker start http-web-server
docker ps -a
docker start ssh-server
ssh admin@172.17.0.3
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
ssh admin@172.17.0.2
ssh test@172.17.0.2
ssh-keygen -f "/root/.ssh/known_hosts" -R "172.17.0.2"
ssh admin@172.17.0.2
docker ps -a
cd /var/log/docker
dir
cat /var/log/docker/tomcat_hello.log
cd /var/lib/docker/containers/bfa13638f7144e8c121e2b11fdf1dfc588a923ab677cac73a184ec1576d3e339/
dir
cd
cat /var/lib/docker/containers/bfa13638f7144e8c121e2b11fdf1dfc588a923ab677cac73a184ec1576d3e339/bfa13638f7144e8c121e2b11fdf1dfc588a923ab677cac73a184ec1576d3e339-json.log
cd /etc/rsyslog.d/
dir
cat wazuh-docker.conf
cd
sudo rsyslogd -f /etc/rsyslog.d/wazuh-docker.conf -N1
systemctl restart rsyslog
docker run hellow-world
cd docker-http
dir
cd docker_http
cd
docker pull hello-world
docker run hello-world
docker ps -a
cd /var/log/docker
dir
ls
ls -l
cd /var/log/messages
cd /var/log
dir
cd syslog.1
cd docker
dir
cd
logger -s "hi"
sudo rsyslogd -N6 | head -10
cd /var/lib/rsyslog
cd /var/lib
dir
cd docker
dir
cd
systemctl status rsyslog.service
cd /var/ossec/etc/ossec.conf
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
systemctl status wazuh-agent.service
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
systemctl status wazuh-agent.service
docker pull hello-world
docker run --log-driver json-file hello-world
docker ps -a
cd /var/lib/docker/containers/
dir
cd fa42d05c50f22780c505ee690b33c230fd1d942bacea53e6ae10711e797a0222/
dir
docker inspect http-web-server
/var/log
cd /var/log
dir
dir syslog
cd syslog
cat syslog
dir
cd journal
dir
cd /var/log
cd docker
dir
cd
cd /var/log
cat syslog.1
dir
cat syslog.2.gz
PuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTYPuTTY
exit
jupyter notebook --no-browser --port=8090 --allow-root
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
docker ps -a
docker rm reverent_brattain 
docker rm elegant_goldberg 
dir
cd wazuh-docker
dir
cd single-node
dir
docker-compose ps
docker-compose -it exec single-node_wazuh.manager_1 bash
dir
docker-compose exec single-node_wazuh.manager_1 bash
docker-compose -i exec single-node_wazuh.manager_1 bash
docker exec single-node_wazuh.manager_1 
docker exec single-node_wazuh.manager_1 bash
docker_compose exec single-node_wazuh.manager_1 bash
docker-compose exec single-node_wazuh.manager_1 bash
docker-compose ps
cd
docker ps -a
docker exec -it 814d5b705d84 bash
cd /var/log
dir
cat syslog
cat syslog.1
/etc/rsyslog.d/
cd /etc/rsyslog.d/
dir
vi wazuh-docker.conf
cd
systemctl restart docker
docker ps -a
systemctl restart rsyslog
docker pull hello-world
docker run hello-world
docker ps -a
cd /var/log
dir
cd docker
dir
cd /etc/rsyslog.d/
vi wazuh-docker.conf
mv wazuh-docker.conf 10-docker.conf
dir
cat 10-docker.conf 
cd
sudo rsyslogd -f /etc/rsyslog.d/10-docker.conf -N1
systemctl status rsyslog.d
systemctl status rsyslog
docker run hello world
docker run hello-world
docker ps -a
cd docker_http
docker run -dit --name my-running-app -p 8080:80 http-server
docker ps -a
docker my-running-app
docker stop my-running-app
cd /var/log
cd docker
dir
cd
docker rm my-running-app
docker rm jovial_faraday 
docker rm modest_bardeen 
docker rm tomcat_hello
docker ps -a
docker exec -it bfa13638f714 bash
docker start http-web-server 
docker exec -it bfa13638f714 bash
docker ps -a
systemctl restart wazuh-agent
systemctl status wazuh-agent
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
docker exec -it 814d5b705d84 bash
sudo ls -la /var/log/docker/
docker run hellow-world
docker pull hellow-world
docker run hello-world
sudo ls -la /var/log/docker/
sudo grep -r "bfa13638f714\[.*\]" /var/log/
sudo journalctl -u docker.service | grep ""bfa13638f714\[.*\]"

docker ps -a
cd /var/log
dir
cat syslog.1
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
systemctl status wazuh-agent.service
vi /var/ossec/etc/ossec.conf
systemctl status wazuh-agent.service
systemctl restart wazuh-agent
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
docker start ecstatic_shamir 
docker ps -a
docker run --log-driver hello-world
docker run --log-driver json-file hello-world
docker ps -a
docker logs hello-world
docker logs ecstatic_shamir 
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
docker ps -a
docker rm keen_archimedes 
cat syslog.1
cd /var/lib/docker/containers/
dir
cd 944d6ddfe7aaf8fbd58ba38ccbda68a44be5eae0f3b171476b7325dffdbcb468/
dir
cat 944d6ddfe7aaf8fbd58ba38ccbda68a44be5eae0f3b171476b7325dffdbcb468-json.log 
ls
docker ps -a
cd /var/lib/docker/containers/
ls
cd 944d6ddfe7aaf8fbd58ba38ccbda68a44be5eae0f3b171476b7325dffdbcb468/
ls
cat 944d6ddfe7aaf8fbd58ba38ccbda68a44be5eae0f3b171476b7325dffdbcb468-json.log 
cd ..
cd /etc
cd docker
ls
json daemon.json 
nano daemon.json 
systemctl restart docker
cd ..
cd /var/log/docker
ls
cd ..
cd etc
ls
grep "rsys" 
ls | grep "rsys" 
cat rsyslog.conf
ls | grep "rsys" 
nano rsyslog.d
cd rsyslog.d/
ls
nano wazuh-docker.conf
ls
systemctl restart docker
systemctl restart rsyslog
docker ps -a
docker restart http-server
doccker restart http-web-server
docker restart http-web-server 
cd /var/log/docker
ls
cd /etc/rsyslog.d
ls
docker ps -a
http-web-server
docker stop http-web-server
cd docker_http
docker build docker run -dit --name web-server2 -p 8080:80 http-server
docker run -dit --name web-server2 -p 8080:80 http-server
cd /var/logs
cd /var/log
dir
cd docker
dir
cd /etc/rsyslog.d
dir
cat syslog.1
cd /var/log
cat syslog.1
cd /etc/rsyslog.d
dir
rm 10-docker.conf
vi wazuh-docker.conf
dir
cat 20-ufw.conf 
cat 21-cl
cat 21-cloudinit.conf 
cat 50-default.conf
vi 50-default.conf 
cd
systemctl restart rsyslog
docker ps -a
docker stop web-server2
docker run hello-world
cd /var/log
dir
cd docker
dir
cd /etc/rsyslog.d
dir
cd etc
cd /etc
dir
cat rsyslog.conf
vi rsyslog.conf 
cd rsyslogd
cd rsyslog.d
dir
vi 50-default.conf 
cat 50-default.conf
cd
systemctl restart rsyslog
docker run hello-world
docker ps -a
cd /var/log
cd docker
dir
cd /var/log
dir
cat syslog
cd
cat /etc/logrotate.d/rsyslog
cd /etc/syslog/syslog.conf
cd /etc/syslog/
cd /etc
dir
cd rsyslog.d
dir
vi 50-default.conf 
cat 50-default.conf 
dir
cd docker_ssh/
dir
docker images
docker container
dokcer container ls
docker container ls
docker ps -a
docker rm vigorous_antonelli 
docker rm hungry_ptolemy 
gpgconf --dry-run --create-socketdir
ssh docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-port2
ssh docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
cd
docker start ssh-server
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
ssh admin@172.17.0.2
ssh connor@172.17.0.2
ssh admin@172.17.0.2
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
ssh admin@172.17.0.2
ssh admin@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1 
ssh admin@172.17.0.2
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
cd /var/ossec/etc/ossec.conf
cat /var/ossec/etc/ossec.conf
vi /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
docker network ls
docker inspect c1 -f "{{json .NetworkSettings.Networks }}"
docker inspect ssh-server -f "{{json .NetworkSettings.Networks }}"
cat /var/ossec/etc/ossec.conf
docker logs single-node_wazuh.manager_1
cd /var/ossec/agentless/
dir
/var/ossec/agentless/register_host.sh list
/var/ossec/agentless/register_host.sh add admin@172.17.0.2 admin [enablepass]
cd
docker ps -a
docker exec -it single-node_wazuh.manager_1 /bin/bash
cd /ect/
cd etc
cd /etc
dir
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1 
nc -zv 172.21.0.3 1514 1515 55000
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server-wazuh
ssh admin@172.17.0.2
docker ps -a

ssh connor@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server-wazuh
ssh admin@172.17.0.2
ssh -o ServerAliveInterval=600 admin@172.17.0.2
docker stop ssh-server-wazuh
docker rm ssh-server-wazuh
ssh admin@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server-wazuh-2
ssh admin@172.17.0.3
exit
docker ps -a
ssh admin@172.17.0.2
admin@172.17.0.2
docker exec -it ssh-server /bin/bash
docker ps -a
docker start ssh-server 
ssh admin@172.17.0.2
docker ps -a
docker exec -it ssh-server /bin/bash
docker exec -it ssh-server bash
ssh admin@172.17.0.2
ssh connor@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1 
ssh admin@172.17.0.2
cd docker_ssh_2
docker build -t ssh_wazuh .
docker run -dit --name ssh-server-wazuh ssh_wazuh
docker ps -a
docker stop ssh-server
docker stop ssh-server-wazuh
docker start ssh-server-wazuh
docker ps -a
docker run -dit --name ssh-server-wazuh -p 4040:40 ssh_wazuh
docker ps -a
docker build -t ssh_wazuh_2 .
docker run -dit --name ssh-server-wazuh-2 ssh_wazuh_2
cd
cd docker_ssh_3
docker build -t ssh_wazuh_3 .
docker run -dit --name ssh-server-wazuh-3 ssh_wazuh_3
docker exec -it ssh-server-wazuh-3 bash
docker ps -a
docker rm ssh-server-wazuh-3
docker run -dit --name ssh-server-wazuh-3 -p 2020:20 ssh_wazuh_3
docker ps -a
docker start ssh-server-wazuh-3
docker ps -a
docker rm ssh-server-wazuh-3
docker ps -a
docker rm ecstatic_shamir 
exit
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
exit
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker inspect single-node_wazuh.manager_1 -f "{{json .NetworkSettings.Networks }}"
docker inspect ssh-server-wazuh-2 -f "{{json .NetworkSettings.Networks }}"
docker network ls
ssh connor@172.21.0.5
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
docker inspect ssh-server-wazuh-2 -f "{{json .NetworkSettings.Networks }}"
docker inspect ssh-server-wazuh -f "{{json .NetworkSettings.Networks }}"
cd /etc/init.d
dir
cd
cd docker_ssh
docker build -t ssh_wazuh_4 .
cd docker_ssh_2
cd
cd docker_ssh_2
docker build -t ssh_wazuh_5 .
docker run -dit --name my-running-port -p 1010:10 ssh_wazuh_5
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port
ssh admin@172.17.0.2
ssh-keygen -f "/root/.ssh/known_hosts" -R "172.17.0.2"
ssh admin@172.17.0.2
ssh connor@@172.17.0.2
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker rm musing_mayer
docker rm nifty_wright
docker rm wizardly_shockley
docker network ps
docker network ls
docker stop ssh-server-wazuh-2
docker rm ssh-server-wazuh-2
docker ps -a
docker stop ssh-server-wazuh
docker rm ssh-server-wazuh
docker images
docker images rm ssh_wazuh_3
docke rm ssh_wazuh_3
docker rm ssh_wazuh_3
docker run -dit --net single-node_default --name ssh-server-wazuh -p 4040:40 ssh_wazuh_2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server-wazuh
docker ps -a
ssh admin@172.21.0.5
docker stop ssh-server-wazuh
docker start ssh-server-wazuh
ssh admin@172.21.0.5
cd docker_ssh
	docker build -t ssh_test .
docker run -dit --name my-running-port -p 4040:40 ssh_test
docker run -dit --name my-running-port -p 2020:20 ssh_test
docker ps -a
docker start my-running-port
docker rm my-running-port
docker run -dit --name my-running-port -p 2020:20 ssh_test
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port
ssh admin@172.17.0.2
docker rm ssh-server
ssh admin@172.17.0.2
docker logs my-running-port
docker ps -a
docker stop my-running-port
docker rm my-running-port
docker rm fervent_kapitsa 
docker ps -a
docker images
docker rmi ssh_wazuh_5
docker images
docker rmi ssh_wazuh_4
docker rmi d8071ad0b742
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker logs my-running-port
docker logs http-web-server
cd /var/logs
cd /var/log
dir
syslog
cat syslog
cat /etc/logrotate.d/rsyslog
cd
cat /usr/lib/rsyslog/rsyslog-rotate
cd /rung
cd /run
cd
vim /etc/logrotate.d/rsyslog
systemctl restart rsyslog
docker run hello-world
cat /var/log/syslog
cat /var/log/syslog1
cat /var/log/syslog.1
cat /var/log/syslog
vim /etc/logrotate.d/rsyslog
cd /etc/logrotate.d
dir
vim /etc/logrotate.d/rsyslog
cd
systemctl restart rsyslog
docker run hello-world
cat /var/log/syslog
cat /var/log/syslog.1
docker run hello-world
systemctl restart rsyslog
cat /var/log/syslog.1
vim /etc/logrotate.d/rsyslog
systemctl restart rsyslog
docker run hello-world
cat /var/log/syslog.1
docker ps -a
cd /var/logs/docker
cd /var/log/docker
dir
cd
cd /var/log/docker
ls -la
cd .
cd  /.
vim /etc/logrotate.d/rsyslog
systemctl restart rsyslog
systemctl restart rsyslog.d
systemctl restart rsyslogd
cat /var/log/syslog.1
docker run hello-world
systemctl restart rsyslog
cat /var/log/syslog.1
docker ps -a
docker rm admiring_pike
docker rm zealous_lovelace
docker rm unruffled_dirac
docker rm amazing_meninsky
docker rm thirsty_merkle
docker ps -a
cd /var/log
dir
rm syslog.1
dir
docker run hello-world
dir
cat syslog
systemctl restart rsyslog
docker run hello-world
dir
cat syslog
dir
rm syslog
dir
systemctl restart rsyslog
docker run hello-world
dir
cat syslog
docker ps -a
docker start http-web-server
cat syslog
dir
cd journal
dir
cd /var/log
cat lastlog
cd docker
dir
cat alternatives.log
cd
docker logs http-web-server
cat /etc/docker/daemon.json
docker inspect 
docker inspect --logging-driver http-web-server
docker inspect --help
docker inspect http-web-server
docker ps -a
docker logs friendly_shannon 
docker logs my-running-port
docker inspect bfa13638f714 | grep -A 5 LogConfig
sudo grep -r "bfa13638f714\[.*\]" /var/log/
sudo grep -r "friendly_shannon\[.*\]" /var/log/
cd /var/log/journal/941d95bd683d4827a3da837ddcc17911/
dir
cat system.journal
cd /var/lib/docker/containers/
dir
docker ps -a
cd 49c01f8822f9f5a7d13b18d12ad0885bf9578a63d498b90d2b26e34d42855899/
dir
cd /var/lib/docker/containers/
cd be74f65ab43898eb65a670e64362f82435b3dea3d6c5dea52951f1fcc54b6182/
dir
cd
cd /var/lib/docker/containers/
dir
cd
cd /var/log
dir
cat syslog
cd journal
dir
ls -la
cd
docker logs http-web-server
docker ps -a
docker rm friendly_shannon
docker rm reverent_chandrasekhar 
docker rm heuristic_wozniak 
docker ps -a
docker rm ssh-server-wazuh
docker stop ssh-server-wazuh
docker rm ssh-server-wazuh
docker images
cd docker_ssh
cd 
cd docker_ssh_2
docker build ssh_wazuh_20 .
docker build -t ssh_wazuh_20 .
docker run -dit --tmpfs /tmp --tmpfs /run --net single-node_default --name ssh-port-20 -p 4040:40 ssh_wazuh_20
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-port-20
docker stop ssh-port-20
docker rm ssh-port-20
docker run -dit --tmpfs /tmp --tmpfs /run --name ssh-port-20 -p 4040:40 ssh_wazuh_20
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-port-20
docker rm ssh-port-20
docker run -dit --tmpfs /tmp --tmpfs /run --net single-node_default --name ssh-port-20 -p 4040:40 ssh_wazuh_20
docker start ssh-port-20
docker ps -a
docker rm ssh-port-20
docker run -dit --net single-node_default --name ssh-port-20 -p 4040:40 ssh_wazuh_20
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-port-20
ssh admin@172.21.0.5
ssh-keygen -f "/root/.ssh/known_hosts" -R "172.21.0.5"
ssh admin@172.21.0.5
clear
cd
docker ps -a
docker stop ssh-port-20
docker stop single-node_wazuh.dashboard_1
docker stop single-node_wazuh.manager_1
docker stop single-node_wazuh.indexer_1
docker rm ssh-port-20
docker rm single-node_wazuh.dashboard_1
docker rm single-node_wazuh.indexer_1
docker rm single-node_wazuh.manager_1
docker ps -a
rm /etc/docker/daemon.json
dir /etc/docker/
dir /var/log/docker
dir /etc/rsyslog.d/
rm /etc/rsyslog.d/wazuh-docker.conf
dir /etc/rsyslog.d/
systemctl restart rsyslog
systemctl restart docker
docker ps -a
docker images
docker run dit --name ssh_port -p 4040:40 ssh_test
cd docker_ssh_2
docker run dit --name ssh_port -p 4040:40 ssh_test
docker build -t ssh_2001_1 .
docker run dit --name ssh_port -p 4040:40 ssh_2001_1
docker run -dit --name ssh_port -p 4040:40 ssh_2001_1
cd
docker ps -a
sudo sysctl -w vm.max_map_count=262144
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
docker-compose up
$ docker run -d 
docker run -d
docker run -d  -v /var/run/docker.sock:/tmp/docker.sock -e LOGSTASH_HOST=192.168.2.181 -e LOGSTASH_PORT=5044 -e SHIPPER_NAME=$(0f5c03850127) bargenson/filebeat
docker ps -a
cd docker_elk
cd docker-elk
docker-compose up
docker networks
docker ls network
docker ps networks
docker network inspect
docker network ls
docker-compose up
sudo docker ps
docker network ls
curl localhost:9200
	docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker-elk-kibana-1
docker ps -a
docker inspect ssh_port
docker ps
curl localhost:9200

docker rm docker-elk-elasticsearch-1
docker stop docker-elk-logstash-1
docker rm docker-elk-logstash-1
docker stop docker-elk-kibana-1
docker rm docker-elk-kibana-1
docker rm docker-elk-setup-1
docker ps -a
cd docker-elk
docker-compose up
docker ps -a
docker run hello-world
docker run -dit --name my-running-app -p 8080:80 http-server
docker logs my-running-app
docker ps -a
docker stop my-running-app
docker rm my-running-app
docker rm sleepy_colden
docker stop docker-elk-logstash-1
docker stop docker-elk-kibana-1
docker stop docker-elk-elasticsearch-1
docker stop interesting_sinoussi
docker rm docker-elk-logstash-1
docker rm docker-elk-kibana-1
docker rm docker-elk-elasticsearch-1 
docker rm interesting_sinoussi 
docker rm docker-elk-setup-1 
docker ps -a
docker stop ssh_port
cd docker-elk-2
docker-compose up
[200~jupyter notebook --no-browser --port=8090 --allow-root
	jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker stop docker-elk-2-kibana-1
docker rm docker-elk-2-kibana-1
docker stop docker-elk-2-logstash-agent-1
docker rm docker-elk-2-logstash-agent-1
docker stop docker-elk-2-logstash-central-1
docker rm docker-elk-2-logstash-central-1
docker stop docker-elk-2-elasticsearch-1
docker rm docker-elk-2-elasticsearch-1
docker stop docker-elk-2-redis-cache-1
docker rm docker-elk-2-redis-cache-1
docker ps -a
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
docker-compose up
curl 192.168.2.181:9200
curl 172.22.0.2:9200
sudo curl localhost:9200
docker pull docker.elastic.co/beats/filebeat:8.6.0
docker run docker.elastic.co/beats/filebeat:8.6.0 setup -E setup.kibana.host=192.168.2.181:5601 -E output.elasticsearch.hosts=["192.168.2.181:9200"]
docker run docker.elastic.co/beats/filebeat:8.6.0 setup -E setup.kibana.host=172.22.0.4:5601 -E output.elasticsearch.hosts=["172.22.0.2:9200"]
docker run -d --net docker-elk_elk
docker run -d --net docker-elk_elk  -v /var/run/docker.sock:/tmp/docker.sock -e LOGSTASH_HOST=172.22.0.3 -e LOGSTASH_PORT=5044 -e SHIPPER_NAME=$(hostname)
docker run -d -v /var/run/docker.sock:/tmp/docker.sock -e LOGSTASH_HOST=172.22.0.3 -e LOGSTASH_PORT=5044 -e SHIPPER_NAME=$(hostname) --net docker-elk_elk
docker run -d -v /var/run/docker.sock:/tmp/docker.sock -e LOGSTASH_HOST=172.22.0.3 -e LOGSTASH_PORT=5044 -e SHIPPER_NAME=$(hostname)
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker-elk-elasticsearch-1
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker-elk-kibana-1
docker network ls
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker-elk-logstash-1
docker ps -a
docker rm adoring_chatterjee
docker rm gifted_merkle
docker stop docker-elk-kibana-1
docker rm docker-elk-kibana-1
docker stop docker-elk-setup-1
docker rm docker-elk-setup-1
docker stop docker-elk-logstash-1
docker rm docker-elk-logstash-1
docker stop docker-elk-elasticsearch-1
docker rm docker-elk-elasticsearch-1
docker ps -a
cd docker-wazuh
dir
cd wazuh-docker
dir
cd single-node
dir
docker compuse docker-compose up
docker-compose up
docker run hello-world
docker ps -a
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node-wazuh.manager-1
cd /var/lib/docker
dir
cd containers
dir
cd 0f5c0385012794c500769d20548f3eb5a89e60dec0968196325d48c0805684d1/
dir
cat 0f5c0385012794c500769d20548f3eb5a89e60dec0968196325d48c0805684d1-json.log
cd /var/lib/docker/containers
cd ffec30f3994f4edc788fdfbcb7165719e93159869162533edf41f4dc68d19087/
dir
cat ffec30f3994f4edc788fdfbcb7165719e93159869162533edf41f4dc68d19087-json.log
docker ps -a
cd /var/ossec/etc/ossec.conf
vim /var/ossec/etc/ossec.conf
stytemctl restart wazuh-agent
systemctl restart wazuh-agent
cat /var/ossec/etc/ossec.conf
vim /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
	jupyter notebook --no-browser --port=8090 --allow-root
cat /var/log/journal/941d95bd683d4827a3da837ddcc17911/user-1000@0270e66c4d324d40acf863dc77cc0f51-0000000000000b0a-0005ef633cd9d18f.journal
cat /var/log/journal/941d95bd683d4827a3da837ddcc17911/system.journal
cd /etc/docker
dir
vim daemon.json
cd
systemctl restart docker
vim /etc/docker/daemon.json
systemctl restart docker
docker run hello-world
cd /var/log
dir
cat syslog
dir
journal
cd journal
dir
cd 941d95bd683d4827a3da837ddcc17911
dir
cd /var/log
dir
cat syslog
vim /etc/docker/daemon.json
docker ps -a
docker logs quizzical_lewin
cd docker_ssh_2
cd docker-ssh
cd
cd docker_ssh
dir
cat Dockerfile
docker ps -a
docker run my-running-port
cd
docker start my-running-port
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port
ssh admin@172.17.0.2
docker ps -a
docker stop my-running-prot
docker stop my-running-port
docker run -dit --name my-running-port-2 -p 3030:30 ssh_test --privileged
docker run  --privileged -dit --name my-running-port-2 -p 3030:30 ssh_test
docker run  --privileged -dit --name my-running-port-3 -p 3030:30 ssh_test
docker ps -a
docker rm my-running-port-2
docker rm quizzical_lewin 
docker rm angry_kepler 
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
ssh admin@172.17.0.2
docker ps -a
docker stop my-running-port-3
docker rm my-running-port-3
docker run  --privileged -dit --name my-running-port-3 -p 3030:30 ssh_test
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
ssh admin@172.17.0.2
docker ps -a
docker stop my-running-port-3
docker rm my-running-port-3
docker rm ssh-port
docker rm ssh_port
docker run  --privileged -dit --name my-running-port-3 -p 3030:30 ssh_test
ssh admin@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
ssh admin@172.17.0.2
docker stop my-running-port-3
docker rm my-running-port-3
docker run -dit --name my-running-port-3 -p 3030:30 ssh_test
ssh admin@172.17.0.2
docker stop my-runnig-port-3
docker stop my-running-port-3
docker rm my-running-port
docker ps -a
docker rm my-running-port
docker rm my-running-port-3
docker run  --privileged -dit --name my-running-port-3 -p 2020:20 ssh_test
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
ssh admin@172.17.0.2
cat /docker-ssh/Dockerfile
cat /docker_ssh/Dockerfile
cd /docker_ssh
cat docker_ssh/Dockerfile
exit
docker ps -a
docker stop ssh
docker rm ssh
docker run -dit --name ssh -p 4040:40 ssh_test
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh
ssh admin@172.17.0.2
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
ssh admin@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-port-3
docker rm my-running-port-3
docker stop my-running-port-3
docker rm my-running-port-3
docker images
docker run -dit --name ssh -p 2020:20 ssh_2001_1
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh
ssh admin@172.17.0.2
ssh connor@172.17.0.2
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
ssh connor@172.17.0.2
docker network
docker network ls
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node_wazuh.manager_1
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node-wazuh.manager-1
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
docker images
docker rmi ssh-server
docker rmi ssh-port
docker rmi ssh-port2
docker rmi tomcat
docker rmi bargenson/filebeat
docker rmi server3
docker rmi server4
docker images
docker rmi ssh_wazuh
docker rmi ssh_wazuh_2
docker rmi ssh_wazuh_3
docker rmi ssh_test
docker rmi ssh_wazuh20
docker rmi ssh_wazuh_20
docker images
docker rmi redis
docker rmi my-apache
docker rmi docker-elk-logstash
docker rmi elasticsearch
docker rmi kibana
docker images
docker rmi docker-elk-setup
docker rmi ssh_2001_1
docker images
docker rmi redis
docker rmi 426156351364
docker rmi ecf6e21a953f
docker rmi 6abbebd2b694
docker rmi bc3d45eba361
docker images
cd /etc
dir
cd docker
di´r
dir
rm daemon.json
cd
docker ps -a
cd docker-ssh
cd docker_ssh
dir
	docker build -t ssh_port .
	docker run -dit --name ssh-port-1 -p 2020:20 ssh_port
docker ps -a
docker inspect ssh-port-1
cd
ssh admin@172.17.0.2
ssh
ssh admin@172.17.0.2
ssh connor@172.17.0.2
ssh localhost
ssh admin@172.17.0.2
sudo service ssh status
	docker exec -it ssh-port-1 /bin/bash
ssh admin@172.17.0.2
docker stop ssh-port-1
docker ps -a
docker rm ssh-port-1
cd docker_ssh_2
docker build -t ssh_wazuh .
docker run -dit --name ssh-wazuh -p 4040:40 ssh_wazuh
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
ssh admin@172.17.0.2
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
docker ps -a
docker rm web-server2
ssh admin@172.17.0.2
sudo lsof -i -n -P | grep LISTEN
cd
systemctl start docker
docker ps -a
sudo systemctl restart docker
docker ps -a
docker rm ssh_wazuh
docker rm ss-_wazuh
docker rm ssh-wazuh
cd docker_ssh
docker images
docker build -t ssh_port_2 .
docker build -t ssh_port_3 .
docker run -dit --name ssh -p 3030:30 ssh_port_3
cd
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh
ssh connor@172.17.0.2
ssh admin@172.17.0.2
cat ~/.ssh/known_hosts
ssh-keygen -f "/root/.ssh/known_hosts" -R "172.17.0.2"
docker ps -a
ssh admin@172.17.0.2
docker exec -it ssh /bin/bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{e
cd docker_ssh_2
docker images
root@playbookvm:~/docker_ssh_2# docker build -t ssh_wazuh_2 .
docker run -dit --net single-node_default --name ssh -p 4040:40 ssh_wazuh
docker run -dit --net single-node_default --name ssh-wazuh -p 4040:40 ssh_wazuh
docker exec -it ssh-wazuh /bin/bash
cd
ssh admin@172.21.0.5
ssh-keygen -f "/root/.ssh/known_hosts" -R "172.21.0.5"
ssh admin@172.21.0.5
ssh connor@172.21.0.5
docker exec -it ssh-wazuh /bin/bash
ssh admin@172.21.0.5
ssh connor@172.21.0.5
docker exec -it ssh-wazuh /bin/bash
docker ps -a
ssh admin@172.17.0.2
sugo apt-get install rsyslog
sudo apt-get install rsyslog
rsyslogd
sudo rsyslogd
ssh admin@172.17.0.2
docker ps -a
docker stop ssh
docker rm ssh
	jupyter notebook --no-browser --port=8090 --allow-root
cd /etc
dir
cd
docker ps -a
docker exec -it single-node-wazuh.manager-1 /bin/bash
ssh connor@172.21.0.5
cd /var/log
dir
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker exec -it ssh-wazuh /bin/bash
cd /var
dir
cd ossec
dir
cd ruleset
dir
cd
dir
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node-wazuh.indexer-1
docker exec -it docker exec -it single-node-wazuh.manager-1 /bin/bash
docker exec -it single-node-wazuh.manager-1 /bin/bash
docker exec -it ssh-wazuh /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
ssh connor@172.21.0.5

docker exec -it single-node-wazuh.manager-1 /bin/bash
docker ps .a
docker ps -a
docker exec -it ssh-wazuh /bin/bash
docker ps -a
docker start http-web-server 
docker exec -it http-web-server /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
docker exec -it http-web-server /bin/bash
docker ps -a
docker stop http-web-server 
cd docker_http
docker images
docker build -t http-server2 .
docker run -dit --name my-running-app -p 8080:80 http-server2
docker exec -it my-running-app /bin/bash
docker build -t http-server-wazuh .
docker images
docker build -t http-server-wazuh .
docker run -dit --name my-running-app-wazuh -p 8080:80 http-server-wazuh
docker stop my-running-app 
docker run -dit --name my-running-app-wazuh -p 9089:80 http-server-wazuh
docker rm my-running-app-wazuh 
docker run -dit --name my-running-app-wazuh -p 9089:80 http-server-wazuh
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
docker network ls
exit
jupyter notebook --no-browser --port=8090 --allow-root
root@playbookvm:~# docker exec -it my-running-app-wazuh /bin/bash
docker exec -it my-running-app-wazuh /bin/bash
docker ps -a
docker rm my-running-app-wazuh
docker stop my-running-app-wazuh
docker rm my-running-app-wazuh 
docker rm admiring_pasteur 
docker rm interesting_chatterjee 
docker rm my-running-app 
[200~docker run -dit --name my-running-app -p 8080:80 my-apache2
docker run -dit --name my-running-app-wazuh -p 8080:80 http-server-wazuh
docker stop my-running-app-wazuh
docker rm my-running-app 
docker rm my-running-app-wazuh 
docker run -dit --net single-node_default --name my-running-app-wazuh -p 8080:80 http-server-wazuh
docker exec -it my-running-app-wazuh /bin/bash
docker logs my-running-app-wazuh 
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
docker ps -a
docker exec -it ssh-wazuh /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
docker exec -it my-running-app-wazuh /bin/bash
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-app-wazuh
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker pull vanhauser/hydra
docker network ls
docker run --net single-node_default vanhauser/hydra hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker ps -a
docker start gifted_keldysh 
docker ps -a
docker run --net single-node_default vanhauser/hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker run --net single-node_default vanhauser/hydra -l connor -P sergeant 172.21.0.6 -s 8080 http-get / -v
docker run --net single-node_default vanhauser/hydra -l connor -p sergeant 172.21.0.6 -s 8080 http-get / -v
docker images
docker run -dit --name my-running-app -p 9090:90 http-server2
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-app
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 9090 http-get / -v
docker ps -a
docker stop my-running-app
docker rm my-running-app
docker rm sweet_almeida 
docker rm laughing_haibt 
docker rm youthful_easley 
docker rm gifted_keldysh 
docker ps -a
docker stop my-running-app-wazuh 
docker start http-web-server 
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http-web-server 
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
cd attacker
hydra -l connor -P ./password-list.txt 172.17.0.3 -s 8080 http-get / -v
docker inspect http-web-server
hydra -l connor -p sergeant 172.17.0.3 -s 8080 http-get / -v
hydra -l marius -p marshall 172.17.0.3 -s 8080 http-get / -v
hydra -l Connor -p sergeant 172.17.0.3 -s 8080 http-get / -v
cd
docker ps -a
docker stop http-web-server 
docker start my-running-app-wazuh 
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-app-wazuh 
hydra -l marius -p marshall 172.21.0.6 -s 8080 http-get / -v
hydra -l marius -P ./password-list.txt 172.21.0.6 -s 8080 http-get / -v
hydra -l marius -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
hydra -l marius -p marshall 172.21.0.6 -s 8080 http-get / -v
docker logs my-running-app-wazuh 
hydra -l marius -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker logs my-running-app-wazuh 
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' my-running-app-wazuh 
hydra -l marius -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker logs my-running-app-wazuh 
docker exec -it my-running-app-wazuh /bin/bash
docker ps -a
docker exec -it single-node-wazuh.indexer-1 /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
ssh connor@172.21.0.5
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -
docker ps -a
docker logs my-running-app-wazuh 
docker ps -a
docker stop my-running-app-wazuh
cd docker_http_2
dir
docker build -t http_error_log .
docker run -dit --name http_test -p 8080:80 http_error_log
docker ps -a
docker start http_error_log
docker start http_test
docker ps -a
docker build -t http_error_log_2 .
docker run -dit --name http_test_2 -p 8080:80 http_error_log_2
docker ps -a
docker build -t http_error_log_3 .
docker run -dit --name http_test_3 -p 8080:80 http_error_log_3
docker ps -a
docker stop http_test_3 
docker build -t http_error_log_4 .
docker run -dit --name http_test_4 -p 8080:80 http_error_log_4
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
cd /root/
ls
touch test
ls
rm test 
exit
cd docker_http_2
docker build -t http4 .
docker run -dit --name http_4 -p 8080:80 http4
docker ps -a
docker build -t http5 .
docker run -dit --name http_5 -p 8080:80 http5
docker ps -a
docker build -t http6 .
docker run -dit --name http_6 -p 8080:80 http6
docker ps -a
docker build -t http7 .
docker run -dit --name http_7 -p 8080:80 http7
docker ps -a
docker stop http_7
docker build -t http8 .
docker run -dit --name http_8 -p 8080:80 http8
docker ps -a
docker build -t http9 .
docker run -dit --name http_9 -p 8080:80 http9
docker ps -a
cd
cd docker_http_3
docker build -t http10 .
docker run -dit --name http_10 -p 8080:80 http10
docker ps -a
docker start http_10
docker stop http_10
docker ps -a
docker rm http_10
docker ps -a
cd
docker rm http_9
docker rm http_8
docker rm http_7
docker rm http_6
docker rm http_5
docker rm http_4
cd docker_http_2
docker build -t http11 .
docker run -dit --name http_11 -p 8080:80 http11
docker ps -a
docker exec -it http_11 /bin/bash
docker ps -a
docker stop http_11
docker build -t http12 .
docker run -dit --name http_12 -p 8080:80 http12
docker ps -a
docker exec -it http_12 /bin/bash
exit
docker ps -a
docker stop http_13
docker network ls
docker start http_13
docker network connect single-node_default http_13
docker inspect --format='{{range .NetworkSettings.Networks}}
http_13


xit
exit





docker ps -a
docker rm http_test_4
docker rm http_test_3
docker rm http_test_2
docker rm http_test
docker start my-running-app-wazuh 
docker ps -a
docker exec -it my-running-app-wazuh /bin/bash
docker stop my-running-app-wazuh 
[200~jupyter notebook --no-browser --port=8090 --allow-root
jupyter notebook --no-browser --port=8090 --allow-root
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http11
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http_11
cd attacker
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
cd
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
hydra -l marius -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
hydra -l connor -p sergeant 172.17.0.3 -s 8080 http-get / -v
hydra -l marius -p marshall 172.17.0.3 -s 8080 http-get / -v
hydra -l connor -p sergeant 172.17.0.3 -s 8080 http-get / -v
hydra -l connor -p test 172.17.0.3 -s 8080 http-get / -v
hydra -l test -p test 172.17.0.3 -s 8080 http-get / -v
hydra -l test -p sergeant 172.17.0.3 -s 8080 http-get / -v
docker ps -a
docker stop http_12
cd docker_http_2
docker build -t http13 .
docker run -dit --name http_13 -p 8080:80 http13
docker ps -a
docker exec -it http_13 /bin/bash
cd
docker ps -a
docker inspect http_13
docker exec -it http_13 /bin/bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http_13
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker ps -a
docker rm http_12
docker rm http_11
docker rm quirky_hertz 
docker exec -it single-node-wazuh.manager-1 /bin/bash
docker exec -it http_13 /bin/bash
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-wazuh
ssh connor@172.21.0.5
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
cd /var/ossec/logs/archives/
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
docker ps -a
docker exec -it http_13 /bin/bash
docker exec -it single-node-wazuh.manager-1 /bin/bash
docker ps -a
docker exec -it ssh-wazuh /bin/bash
cd docker_http_3
dir
docker build -t http_14 .
docker run -dit --name http_14 -p 8080:80 http_14
docker ps -a
docker stop http_13
docker start http_14
docker ps -a
docker build -t http_15 .
docker run -dit --name http_15 -p 8080:80 http_15
docker ps -a
cd
docker start http_13
docker ps -a
docker rm http_14
docker rm http_15
cd docker_http_2
dir
cd
docker stop http_13
docker run -dit --net single-node_default --name http_13_1 -p 8080:80 http13
docker inspect http_13_1
docker exec -it http_13_1 /bin/bash
docker ps -a

docker network ls
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
hydra -l connor -P ./attacker/password-list.txt 172.17.0.3 -s 8080 http-get / -v
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
ls -l /usr/local/apache2/logs/error_log
ls -l usr/local/apache2/logs/error_log
cat /usr/local/apache2/logs/error_log
cd /usr
dir
cd logal
cd local
cd apache1
cd apache2
dir
cd etc
dir
cd /usr/local/apache2
sudo /usr/local/apache2
cd usr/local/apache2
cd /usr/local/apache2
cd
cd /usr/local/apache2
cd usr/local/apache2
cd /usr/local
dir
ls -a
cd /.apache2
cd .apache2
cd etc
dir
docker exec -it http_13_1 /bin/bash
docker ps -a
docker stop http_13_1
cd docker_http_3
docker build -t http16 .
docker run -dit --name http_16 -p 8080:80 http16
docker ps -a
docker build -t http17 .
docker run -dit --name http_17 -p 8080:80 http17
docker ps -a
docker build -t http18 .
docker run -dit --name http_18 -p 8080:80 http18
docker ps -a
docker build -t http19 .
docker run -dit --name http_19 -p 8080:80 http19
docker ps -a
docker stop http_19
docker build -t http20 .
docker run -dit --name http_20 -p 8080:80 http20
docker ps -a
docker build -t http21 .
docker run -dit --name http_21 -p 8080:80 http21
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
docker exec -it single-node-wazuh.manager-1 /bin/bash
docker ps -a
docker exec -it http_21 /bin/bash
docker stop http_21
cd docker_http_3
docker build -t http22 .
docker run -dit --net single-node_default --name http_22 -p 8080:80 http22
docker ps -a
docker exec -it http_22 /bin/bash
docker exec -it http_22 /bin/bash
docker inspect http_22
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker ps -a
docker stop http_22
cd docker_http_3
docker build -t http23 .
docker run -dit --net single-node_default --name http_23 -p 8080:80 http23
docker exec -it http_23 /bin/bash
docker ps -a
docker inspect http_23
hydra -l connor -p sergeant 172.21.0.6 -s 8080 http-get /
hydra -l test -p sergeant 172.21.0.6 -s 8080 http-get /
hydra -l connor -P ./attacker/password-list.txt 172.17.0.2 -s 8080 http-get / -v
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
docker exec -it single-node-wazuh.manager-1 /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
hydra -l connor -P ./attacker/password-list.txt 172.21.0.6 -s 8080 http-get / -v
hydra -l test -P test 172.21.0.6 -s 8080 http-get / -v
hydra -l test -p test 172.21.0.6 -s 8080 http-get / -v
hydra -l connor -p test 172.21.0.6 -s 8080 http-get / -v
docker exec -it http_23 /bin/bash
docker ps -a
docker rm http_13
docker rm http_13_1
docker rm http_16
docker rm http_17
docker rm http_18
docker rm http_19
docker rm http_20
docker rm http_21
docker rm http_22
docker ps -a
docker exec -it single-node-wazuh.manager-1 /bin/bash
hydra -l connor -p test 172.21.0.6 -s 8080 http-get /
docker ps -a
docker exec -it http_23 /bin/bash
docker ps -a
hydra -l connor -p sergeant 172.21.0.6 -s 8080 http-get /
docker exec -it single-node-wazuh.manager-1 /bin/bash
docker exec -it ssh_wazuh /bin/bash
docker ps .a
docker ps -a
docker exec -it ssh-wazuh /bin/bash
docker ps -a
docker container rename http_23 apache-http-server
docker ps -a
docker rm http-web-server
docker rm my-running-app-wazuh 
docker ps -a
docker inspect ssh
ssh admin@172.17.0.2
docker exec -it ssh-wazuh /bin/bash
docker exec -it ssh /bin/bash
docker ps .a
docker ps -a
dir
cd wazuh-docker
docker-compose up
dir
cd single-node
dir
docker-compose up
cd
docker ps -a
docker rm single-node-wazuh.dashboard-1
docker rm single-node-wazuh.manager-1
docker rm single-node-wazuh.indexer-1
docker ps -a
docker start clear
clear
docker ps -a
docker images
cd
docker service inspect
docker service ls
docker service ps
docker service ps --help
docker service inspect --help
clear
ps aux | grep docker | wc -l
ps aux | grep docker
sudo snap stop docker
docker ps -a
docker start
ps aux | grep docker
systemctl start docker
docker ps -a
curl -sSL https://get.docker.com/ | sh
sudo snap enable docker
sudo start docker
sudo snap start docker
docker ps -a
sudo snap stop docker
sudo systemctl start docker
docker ps -a
sudo systemctl restart docker
sudo systemctl start docker
docker ps -a
sudo ps aux | grep docker
sudo systemctl start docker
docker ps -a
sudo snap remove docker
docker ps -a
sudo dockerd
vim /etc/docker/daemon.json:
cat /etc/docker/daemon.json:
sudo dockerd
vim /etc/docker/daemon.json:
docker ps -a
sudo systemctl enable docker
sudo systemctl daemon-reload
docker ps -a
apt-get install --reinstall docker
dir
snap stop docker
docker
docker ps -a
docker info
ls -l /var/run/docker.sock
service docker start
systemctl status docker.service
cd /etc/docker/
dir
vim daemon.json
cd
docker ps .a
docker ps -a
systemctl status docker
sudo systemctl restart docker
systemctl status docker.service
sudo systemctl enable docker.service
systemctl status docker.service
systemctl status docker
sudo systemctl restart docker
systemctl status docker.service
jupyter notebook --no-browser --port=8090 --allow-root
sudo journalctl -u docker
cd /etc/docker
dir
cat daemon.json
cat daemon.json:
rm daemon.json
rm daemon.json:
dir
cd docker_http_3
dir
vim admin.html
vim index.html
cat index.html
cd
ssh connor@172.21.0.6
exit
jupyter notebook --no-browser --port=8090 --allow-root
docker ps -a
systemctl start docker
systemctl status docker.service
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker ps -a
systemctl status docker
ls -l /var/run/docker.sock
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker ps -a
docker start ssh-wazuh
docker ps -a
docker start apache-http-server
docker inspect ssh-wazuh
docker ps .a
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node-wazuh.manager-1 
docker stop ssh-wazuh
docker star ssh
docker start ssh
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh
docker exec -it some-container /bin/bash
docker exec -it ssh /bin/bash
docker ps -a
docker stop apache-http-server
docker rename apache-http-server http-old
docker rename ssh-wazuh ssh-old
docker rename ssh ssh-test
docker ps -a
docker stop ssh-test
docker ps -a
cd docker_http_3
dir
cat Dockerfile
cat index.html
dir
docker images
docker build -t apache-http-wazuh .
docker run -dit --net single-node_default --name http-server -p 8080:80 apache-http-wazuh
docke ps -a
docker ps -a
docker inspect http-server
docker rm http-server
docker stop http-server
docker images
docker images rm apache-http-wazuh
docker rmi apache-http-wazuh
docker ps -a
docker rm http-server
docker rmi apache-http-wazuh
docker images
docker build -t apache-http-wazuh .
docker run -dit --net single-node_default --name http-server -p 8080:80 apache-http-wazuh
docker exec -it apache-http-wazuh /bin/bash
docker exec -it http-server /bin/bash
cd
docker ps -a
docker stop http-server
docker start http-old
docker exec -it http-old /bin/bash
docker ps -a
docker stop http-server
docker stop http-old
docker start http-server
docker exec -it http-server /bin/bash
cd docker_ssh_2
dir
cat dockerfile
cat Dockerfile
docker ps -a
docker build -t ssh-wazuh .
docker run -dit --net single-node_default --name ssh-server -p 3030:30 ssh-wazuh
docker ps -a
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
ssh connor@172.21.0.6
docker exec -it ssh-server /bin/bash
cd
ssh connor@172.21.0.6
docker exec -it ssh-server /bin/bash
ssh connor@172.21.0.6
docker ps -a
docker inspect ssh-server
ssh admin@"172.21.0.1"
ssh admin@172.21.0.6
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-server
docker ps .a
docker ps -a
docker exec -it http-server /bin/bash
cd attacker
dir 
ssh-shell2.py
python ssh-shell2.py
python3 ssh-shell2.py
docker exec -it ssh-server /bin/bash
ssh admin@172.21.0.6~
ssh admin@172.21.0.6
ssh connor@172.21.0.6
who
ssh clara@172.21.0.6
ssh connor@172.21.0.6
docker ps -a
ssh connor@172.21.0.6
ssh admin@172.21.0.6
ssh connor@172.21.0.6
cd attacker
dir
python3 ssh-shell2.py
python3 ssh-shell.py
paramiko
python3 ssh-shell.py
ssh admin@172.21.0.6
docker exec -it ssh-server /bin/bash
docker ps -a
docker start ssh-server
docker ps -a
docker exec -it ssh-server /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
cd attacker
python3 ssh-shell.py
docker exec -it ssh-server /bin/bash
ssh admin@172.21.0.6
docker ps -a
docker exec -it http-server /bin/bash
cd docker-http
vim index.html
cat index.html
cd
docker exec -it http-server /bin/bash
jupyter notebook --no-browser --port=8090 --allow-root
jupyter notebook --no-browser --port=8090 --allow-root
docker exec -it http-server /bin/bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http-server
docker ps -a
docker start ssh-server
docker start http-server
docker exec -it http-server /bin/bash
docker exec -it ssh-server /bin/bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http-server
docker stop http-server
docker stop ssh-server
docker start http-server
docker start ssh-server
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' http-server
hydra -l connor -P ./attacker/password-list.txt 172.21.0.5 -s 8080 http-get / -v
docker exec -it http-server /bin/bash
docker exec -it ssh-server /bin/bash
ssh admin@172.21.0.6
hydra -l connor -p sergeant 172.21.0.5 -s 8080 http-get /
hydra -l connor -p test 172.21.0.5 -s 8080 http-get /
hydra -l connor -P ./attacker/password-list.txt 172.21.0.5 -s 8080 http-get / -v
docker ps -a
docker exec -it single-node-wazuh.manager /bin/bash
docker exec -it single-node-wazuh.manager-1 /bin/bash
ssh admin@172.21.0.6
docker ps -a
jupyter notebook --no-browser --port=8090 --allow-root
pip install jupyter
jupyter notebook --no-browser --port=8090 --allow-root
apt-get update
pip install jupyter
cd attacker
dir
vim password-list.txt 
hydra -l connor -P ./attacker/password-list.txt 172.21.0.5 -s 8080 http-get / -v
cd
hydra -l connor -P ./attacker/password-list.txt 172.21.0.5 -s 8080 http-get / -v
python3 /attacker/ssh-shell.py
python3 attacker/ssh-shell.py
ssh clara@172.21.0.6
ssh marius@172.21.0.6
docker ps -a
docker start http-server
docker start ssh-server
ifup
apt-get install ifupdown
ifup
