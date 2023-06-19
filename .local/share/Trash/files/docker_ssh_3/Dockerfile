FROM ubuntu:latest
RUN apt update && apt install  openssh-server sudo -y
RUN apt update && apt install curl sudo -y

RUN curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='172.21.0.3' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb
RUN sudo update-rc.d wazuh-agent defaults 95 10
RUN sudo service wazuh-agent start

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 admin 
RUN  echo 'admin:admin' | chpasswd
#RUN service ssh start
RUN useradd -ms /bin/bash  connor
RUN  echo 'connor:connor' | chpasswd
RUN useradd -ms /bin/bash  marshall
RUN  echo 'marshall:marshall' | chpasswd
EXPOSE 44
CMD ["/usr/sbin/sshd","-D"]