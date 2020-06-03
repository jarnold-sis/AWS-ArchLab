#!/bin/bash
# Configuration
PROGRAM='Shibboleth Discovery Service'

##################################### Functions Definitions
function checkos () {
    platform='unknown'
    unamestr=`uname`
    if [[ "${unamestr}" == 'Linux' ]]; then
        platform='linux'
    else
        echo "[WARNING] This script is not supported on MacOS or FreeBSD"
        exit 1
    fi
    echo "${FUNCNAME[0]} Ended"
}

function setup_environment_variables() {
    REGION=$(curl -sq http://169.254.169.254/latest/meta-data/placement/availability-zone/)
      #ex: us-east-1a => us-east-1
    REGION=${REGION: :-1}

    ETH0_MAC=$(/sbin/ip link show dev eth0 | /bin/egrep -o -i 'link/ether\ ([0-9a-z]{2}:){5}[0-9a-z]{2}' | /bin/sed -e 's,link/ether\ ,,g')

    _userdata_file="/var/lib/cloud/instance/user-data.txt"

    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    EIP_LIST=$(grep EIP_LIST ${_userdata_file} | sed -e 's/EIP_LIST=//g' -e 's/\"//g')

    LOCAL_IP_ADDRESS=$(curl -sq 169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/local-ipv4s/)

    CWG=$(grep CLOUDWATCHGROUP ${_userdata_file} | sed 's/CLOUDWATCHGROUP=//g')

    ASGN=$(grep ClusterName ${_userdata_file} | sed 's/ClusterName=//g')

    # LOGGING CONFIGURATION
    SHIBHOST_MNT="/var/log/shibhost"
    SHIBHOST_LOG="shibhost.log"
    echo "Setting up host session log in ${SHIBHOST_MNT}/${SHIBHOST_LOG}"
    mkdir -p ${SHIBHOST_MNT}
    SHIBHOST_LOGFILE="${SHIBHOST_MNT}/${SHIBHOST_LOG}"
    SHIBHOST_LOGFILE_SHADOW="${SHIBHOST_MNT}/.${SHIBHOST_LOG}"
    touch ${SHIBHOST_LOGFILE}
    if ! [ -L "$SHIBHOST_LOGFILE_SHADOW" ]; then
      ln ${SHIBHOST_LOGFILE} ${SHIBHOST_LOGFILE_SHADOW}
    fi
    mkdir -p /usr/bin/shibhost
    touch /tmp/messages
    chmod 770 /tmp/messages

    export REGION ETH0_MAC EIP_LIST CWG ASGN SHIBHOST_MNT SHIBHOST_LOG SHIBHOST_LOGFILE SHIBHOST_LOGFILE_SHADOW \
          LOCAL_IP_ADDRESS INSTANCE_ID
}

function verify_dependencies(){
    if [[ "a$(which aws)" == "a" ]]; then
      pip install awscli
    fi
    echo "${FUNCNAME[0]} Ended"
}

function osrelease () {
    OS=`cat /etc/os-release | grep '^NAME=' |  tr -d \" | sed 's/\n//g' | sed 's/NAME=//g'`
    if [[ "${OS}" == "Ubuntu" ]]; then
        echo "Ubuntu"
    elif [[ "${OS}" == "Amazon Linux AMI" ]] || [[ "${OS}" == "Amazon Linux" ]]; then
        echo "AMZN"
    elif [[ "${OS}" == "CentOS Linux" ]]; then
        echo "CentOS"
    elif [[ "${OS}" == "SLES" ]]; then
        echo "SLES"
    else
        echo "Operating System Not Found"
    fi
    echo "${FUNCNAME[0]} Ended" >> /var/log/cfn-init.log
}

function harden_ssh_security () {
    # Allow ec2-user only to access this folder and its content
    #chmod -R 770 /var/log/shibhost
    #setfacl -Rdm other:0 /var/log/shibhost

    # Make OpenSSH execute a custom script on logins
    echo -e "\nForceCommand /usr/bin/shibhost/shell" >> /etc/ssh/sshd_config



cat <<'EOF' >> /usr/bin/shibhost/shell
bastion_mnt="/var/log/shibhost"
bastion_log="shibhost.log"
# Check that the SSH client did not supply a command. Only SSH to instance should be allowed.
export Allow_SSH="ssh"
export Allow_SCP="scp"
if [[ -z $SSH_ORIGINAL_COMMAND ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SSH ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SCP ]]; then
#Allow ssh to instance and log connection
    if [[ -z "$SSH_ORIGINAL_COMMAND" ]]; then
        /bin/bash
        exit 0
    else
        $SSH_ORIGINAL_COMMAND
    fi
log_shadow_file_location="${bastion_mnt}/.${bastion_log}"
log_file=`echo "$log_shadow_file_location"`
DATE_TIME_WHOAMI="`whoami`:`date "+%Y-%m-%d %H:%M:%S"`"
LOG_ORIGINAL_COMMAND=`echo "$DATE_TIME_WHOAMI:$SSH_ORIGINAL_COMMAND"`
echo "$LOG_ORIGINAL_COMMAND" >> "${bastion_mnt}/${bastion_log}"
log_dir="/var/log/shibhost/"

else
# The "script" program could be circumvented with some commands
# (e.g. bash, nc). Therefore, I intentionally prevent users
# from supplying commands.

echo "This host supports interactive sessions only. Do not supply a command"
exit 1
fi
EOF

    # Make the custom script executable
    chmod a+x /usr/bin/shibhost/shell

    release=$(osrelease)
    if [[ "${release}" == "CentOS" ]]; then
        semanage fcontext -a -t ssh_exec_t /usr/bin/shibhost/shell
    fi

    echo "${FUNCNAME[0]} Ended"
}

function setup_logs () {

    echo "${FUNCNAME[0]} Started"

    if [[ "${release}" == "SLES" ]]; then
        curl 'https://s3.amazonaws.com/amazoncloudwatch-agent/suse/amd64/latest/amazon-cloudwatch-agent.rpm' -O
        zypper install --allow-unsigned-rpm -y ./amazon-cloudwatch-agent.rpm
        rm ./amazon-cloudwatch-agent.rpm
    elif [[ "${release}" == "CentOS" ]]; then
        curl 'https://s3.amazonaws.com/amazoncloudwatch-agent/centos/amd64/latest/amazon-cloudwatch-agent.rpm' -O
        rpm -U ./amazon-cloudwatch-agent.rpm
        rm ./amazon-cloudwatch-agent.rpm
    elif [[ "${release}" == "Ubuntu" ]]; then
        curl 'https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb' -O
        dpkg -i -E ./amazon-cloudwatch-agent.deb
        rm ./amazon-cloudwatch-agent.deb
    elif [[ "${release}" == "AMZN" ]]; then
        curl 'https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm' -O
        rpm -U ./amazon-cloudwatch-agent.rpm
        rm ./amazon-cloudwatch-agent.rpm
    fi

    cat <<EOF >> /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
    "logs": {
        "force_flush_interval": 5,
        "logs_collected": {
            "files": {
                "collect_list": [
  {
      "file_path": "${SHIBHOST_LOGFILE_SHADOW}",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-shibhost",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  },
  {
      "file_path": "/var/log/shibboleth/shibd.log",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-shibd",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  },
  {
      "file_path": "/var/log/httpd/access_log",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-httpd-access",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  },
  {
      "file_path": "/var/log/httpd/error_log",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-httpd-error",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  },
  {
      "file_path": "/var/log/yum.log",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-yum",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  },
  {
      "file_path": "/var/log/messages",
      "log_group_name": "${CWG}",
      "log_stream_name": "${ASGN}-{instance_id}-messages",
      "timestamp_format": "%Y-%m-%d %H:%M:%S",
      "timezone": "UTC"
  }

                ]
            }
        }
    }
}
EOF

    if [ -x /bin/systemctl ] || [ -x /usr/bin/systemctl ]; then
        systemctl enable amazon-cloudwatch-agent.service
        systemctl restart amazon-cloudwatch-agent.service
    else
        start amazon-cloudwatch-agent
    fi
}

function setup_os () {

    echo "${FUNCNAME[0]} Started"

    if [[ "${release}" == "AMZN" ]] || [[ "${release}" == "CentOS" ]]; then
        bash_file="/etc/bashrc"
    else
        bash_file="/etc/bash.bashrc"
    fi

cat <<EOF >> "${bash_file}"
#Added by Linux host bootstrap
declare -rx IP=\$(echo \$SSH_CLIENT | awk '{print \$1}')
declare -rx SHIBHOST_LOG=${SHIBHOST_LOGFILE}
declare -rx PROMPT_COMMAND='history -a >(logger -t "[ON]:\$(date)   [FROM]:\${IP}   [USER]:\${USER}   [PWD]:\${PWD}" -s 2>>\${SHIBHOST_LOG})'
EOF

    echo "Defaults env_keep += \"SSH_CLIENT\"" >> /etc/sudoers

    if [[ "${release}" == "Ubuntu" ]]; then
        user_group="ubuntu"
    elif [[ "${release}" == "CentOS" ]]; then
        user_group="centos"
    elif [[ "${release}" == "SLES" ]]; then
        user_group="users"
    else
        user_group="ec2-user"
    fi

    chown root:"${user_group}" "${SHIBHOST_MNT}"
    chown root:"${user_group}" "${SHIBHOST_LOGFILE}"
    chown root:"${user_group}" "${SHIBHOST_LOGFILE_SHADOW}"
    chmod 662 "${SHIBHOST_LOGFILE}"
    chmod 662 "${SHIBHOST_LOGFILE_SHADOW}"
    chattr +a "${SHIBHOST_LOGFILE}"
    chattr +a "${SHIBHOST_LOGFILE_SHADOW}"
    touch /tmp/messages
    chown root:"${user_group}" /tmp/messages

    if [[ "${release}" == "CentOS" ]]; then
        restorecon -v /etc/ssh/sshd_config
        systemctl restart sshd
    fi

    if [[ "${release}" == "SLES" ]]; then
        echo "0 0 * * * zypper patch --non-interactive" > ~/mycron
    elif [[ "${release}" == "Ubuntu" ]]; then
        apt-get install -y unattended-upgrades
        echo "0 0 * * * unattended-upgrades -d" > ~/mycron
    else
        echo "0 0 * * * yum -y update --security" > ~/mycron
    fi

    crontab ~/mycron
    rm ~/mycron

    echo "${FUNCNAME[0]} Ended"
}        

##################################### End Function Definitions
# Call checkos to ensure platform is Linux
checkos
# Verify dependencies are installed.
verify_dependencies
# Assuming it is, setup environment variables.
setup_environment_variables
# Disable TCP Forwarding
awk '!/AllowTcpForwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
harden_ssh_security
# Disable X11 Forwarding
awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
# Complete OS and Logging Setup 
release=$(osrelease)
if [[ "${release}" == "Operating System Not Found" ]]; then
    echo "[ERROR] Unsupported Linux Bastion OS"
    exit 1
else
    setup_os
    setup_logs
fi