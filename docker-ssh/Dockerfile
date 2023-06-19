FROM ubuntu:latest

RUN apt update && apt install  openssh-server sudo curl -y
#RUN apt update && apt install curl -y

RUN sudo apt-get -y install rsyslog
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN rsyslogd

RUN curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='172.21.0.4' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb
RUN sudo update-rc.d wazuh-agent defaults 95 10
RUN sudo service wazuh-agent start

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 admin 
RUN  echo 'admin:admin' | chpasswd
RUN service ssh start
RUN useradd -ms /bin/bash  connor
RUN  echo 'connor:cKennway' | chpasswd
RUN useradd -ms /bin/bash  marshall
RUN  echo 'marshall:mLinus' | chpasswd
RUN useradd -ms /bin/bash  marius
RUN  echo 'marius:mPolo' | chpasswd
RUN useradd -ms /bin/bash  clara
RUN  echo 'clara:cFilia' | chpasswd
RUN useradd -ms /bin/bash  christina
RUN  echo 'christina:cAbruzzo' | chpasswd
EXPOSE 33
CMD ["/usr/sbin/sshd", "-D"]