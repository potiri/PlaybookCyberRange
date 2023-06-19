FROM ubuntu:latest
RUN apt update && apt install  openssh-server sudo -y
RUN sudo apt-get -y install rsyslog
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
RUN rsyslogd

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 admin
RUN  echo 'admin:admin' | chpasswd
RUN useradd -ms /bin/bash  connor
RUN  echo 'connor:connor' | chpasswd
RUN useradd -ms /bin/bash  marshall
RUN  echo 'marshall:marshall' | chpasswd

RUN service ssh start
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]