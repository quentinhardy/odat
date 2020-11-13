FROM ubuntu:latest
# Reduce output from debconf
env UBUNTU_FRONTEND noninteractive

ENV TZ=Asia/Dubai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone


# Install python-dev, alien and libaio1 package (for sqlplus) and some python libraries
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils git wget libaio1 alien build-essential dpkg-dev python3-dev python3-pip python3-scapy ca-certificates python3-setuptools python3-pip
WORKDIR /tmp
# Generate DEB files from RPM files to install instant client basic, sdk and sqlplus
ADD oracle-instantclient11.2-basic-11.2.0.4.0-1.x86_64.rpm /tmp/oracle-instantclient11.2-basic-11.2.0.4.0-1.x86_64.rpm
ADD oracle-instantclient11.2-devel-11.2.0.4.0-1.x86_64.rpm /tmp/oracle-instantclient11.2-devel-11.2.0.4.0-1.x86_64.rpm
ADD oracle-instantclient11.2-sqlplus-11.2.0.4.0-1.x86_64.rpm /tmp/oracle-instantclient11.2-sqlplus-11.2.0.4.0-1.x86_64.rpm
RUN ls /tmp
RUN alien --to-deb oracle-instantclient11.2-basic-11.2.0.4.0-1.x86_64.rpm oracle-instantclient11.2-sqlplus-11.2.0.4.0-1.x86_64.rpm oracle-instantclient11.2-devel-11.2.0.4.0-1.x86_64.rpm
RUN ls /tmp
RUN dpkg -i oracle-instantclient11.2-basic_11.2.0.4.0-2_amd64.deb oracle-instantclient11.2-sqlplus_11.2.0.4.0-2_amd64.deb oracle-instantclient11.2-devel_11.2.0.4.0-2_amd64.deb
RUN bash -c 'rm *.{deb,rpm}'
# Define Oracle env variables
RUN bash -c 'echo "export ORACLE_HOME=/usr/lib/oracle/12.1/client64" >> /etc/profile'
RUN bash -c 'echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:\$ORACLE_HOME/lib" >> /etc/profile'
RUN bash -c 'echo "export PATH=\$ORACLE_HOME/bin:\$PATH" >> /etc/profile'
# Create the /etc/ld.so.conf.d/oracle.conf file and add the path to Oracle home
RUN bash -c 'echo "/usr/lib/oracle/12.1/client64/lib/" > /etc/ld.so.conf.d/oracle.conf'
RUN bash -c 'ldconfig'
# Install CX_Oracle
RUN bash -cl 'pip3 install cx_Oracle -i https://pypi.python.org/simple/'
# Install some python libraries and pyinstaller
RUN pip3 install colorlog termcolor pycrypto argcomplete pyinstaller passlib -i https://pypi.python.org/simple/
RUN activate-global-python-argcomplete
# Change to /root et clone odat project
WORKDIR /root
RUN git clone https://github.com/quentinhardy/odat.git
RUN ln -s /usr/bin/python3 /usr/bin/python
WORKDIR odat
