FROM httpd:2.4
RUN mkdir /var/log/httpd
COPY ./my-httpd.conf /usr/local/apache2/conf/httpd.conf
COPY ./index.html /usr/local/apache2/htdocs/index.html
COPY ./htpasswd /usr/local/apache2/htpasswd

RUN apt update && apt install lsb-release sudo curl -y
RUN curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='172.21.0.4' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb
RUN sudo update-rc.d wazuh-agent defaults 95 10
#RUN sudo service wazuh-agent start