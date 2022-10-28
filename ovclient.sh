#!/bin/bash


die() { #{{{
	printf "ERROR: $1\n"; exit;
}
#}}}

check_status() { #{{{
	# As long as ./easyrsa returns 0 (success) we don't bother the non-verbose users
	should_be_empty=`echo $1 | sed 's/0//g'`
	[ "X$should_be_empty" == "X" ] || { cat $2; die "Failed for $client" ; }
	[ "X$VERBOSE" == "X1" ] && { cat $2; }
}
#}}}
revoke() { #{{{
	log=`mktemp`
	group_name=`groups nobody | cut -f2 -d: | cut -f2 -d' '`
	groups nobody | grep -q " $group_name" || { die "Failed at detecting group for user 'nobody'"; }
	cd /etc/openvpn/server/easy-rsa/
	./easyrsa --batch revoke "$1" &>> $log

	status+=$?;
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl &>> $log
	status+=$?;
	rm -f "/etc/openvpn/server/easy-rsa/pki/private/$1.key" 2>/dev/null
	rm -f "/etc/openvpn/server/easy-rsa/pki/issued/$1.crt" 2>/dev/null
	rm -f "/etc/openvpn/server/easy-rsa/pki/reqs/$1.req" 2>/dev/null
	rm -f /etc/openvpn/server/crl.pem
	cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	id "$1" &>/dev/null && { userdel "$1"; }
	rm "/etc/openvpn/google-authenticator/$1" 2>/dev/null

	check_status $status $log 
	echo "OK! $1 revoked";
}
#}}}
add() { #{{{
	log=`mktemp`
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$1")
	client="vpn_$client"
	[ -e /etc/openvpn/server/easy-rsa/pki/issued/$client.crt ] && { die "$client exists"; }
	add_client_google_auth $client
	cd /etc/openvpn/server/easy-rsa/
	rm -f /etc/openvpn/server/easy-rsa/pki/private/$client.key 2>/dev/null

	EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full $client nopass &>> $log
	status+=$?
	mkdir -p $OVUSERHOME/$client
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/$client.crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/$client.key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > $OVUSERHOME/$client/${client}.ovpn
	chown -R $OVUSER $OVUSERHOME/$client

	check_status $status $log 
	echo "OK! $client created"
}
#}}}
list() { #{{{
	[ "X$1" == "Xalphabet" ] && {
		ls /etc/openvpn/server/easy-rsa/pki/issued/ | grep -v 'server.crt' | while read i; do
			echo $i | sed 's/\.crt$//'
		done
	} 
	[ "X$1" == "Xdate" ] && {
		ls -tlh /etc/openvpn/server/easy-rsa/pki/issued/ | grep -v 'server.crt' | while read i; do
			echo $i | sed 's/\.crt$//'
		done
	} 
}
#}}}

add_client_google_auth() { # {{{
	cat /etc/openvpn/server/client-common.txt | grep -q '# USE-GOOGLE-AUTHENTICATOR' || { return; }
	[ "X$GPASSWORD" == "X" ] && { die "Since you enabled Google Authenticator you need to call client.sh -p <password>" ; }
	mkdir -p $OVUSERHOME/$1
	useradd --shell=/bin/false --no-create-home $1
	echo "$1:$GPASSWORD" | chpasswd
	google-authenticator -l "$1" -t -d -f -r 3 -Q UTF8 -R 30 -w3 -e1 -s /etc/openvpn/google-authenticator/$1 | grep 'https://www.google.com'  > $OVUSERHOME/$1/meta_$1.txt
	chown gauth:gauth /etc/openvpn/google-authenticator/*
}

# }}}
install_google_authenticator () { #{{{
	apt update
	apt install -y libpam-google-authenticator
	cat /etc/group | grep -q gauth ||          { addgroup gauth; }
	cut -d: -f1 /etc/passwd | grep -q gauth || { useradd -g gauth gauth; }
	mkdir -p /etc/openvpn/google-authenticator
	chown gauth:gauth /etc/openvpn/google-authenticator
	chmod 0700 /etc/openvpn/google-authenticator

	temp=`mktemp`
	unset PAMPLUGIN
	unset GAUTH

	[ -e "/usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so" ] && { 
		PAMPLUGIN="/usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so";
	}

	[ -e "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so" ] && { 
		PAMPLUGIN="/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so";
	}

	[ -e "/lib/security/pam_google_authenticator.so" ] && { 
		GAUTH="/lib/security/pam_google_authenticator.so";
	}
	[ -e "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so" ] && { 
		GAUTH="/lib/x86_64-linux-gnu/security/pam_google_authenticator.so";
	}

	[ "X$PAMPLUGIN" == "X" ] &&   { "Stop. Cannot find /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"; exit; }
	[ "X$GAUTH" == "X" ] && { "Stop. Cannot find /lib/x86_64-linux-gnu/security/pam_google_authenticator.so";  exit; }

	cat /etc/openvpn/server/server.conf | grep -v "plugin $PAMPLUGIN /etc/pam.d/openvpn" > $temp
	echo "plugin $PAMPLUGIN /etc/pam.d/openvpn" >> $temp
	cat $temp > /etc/openvpn/server/server.conf

	echo "auth required $GAUTH secret=/etc/openvpn/google-authenticator/\${USER} user=gauth forward_pass" > /etc/pam.d/openvpn;
}
#}}}
enable_google_authenticator() { #{{{
	temp=`mktemp`
	cat /etc/openvpn/server/client-common.txt | grep -v "remote-cert-tls server" | grep -v "auth-nocache" | grep -v "auth-user-pass" | grep -v "reneg-sec" > $temp
	cat << EOF >> $temp
reneg-sec 30000			# USE-GOOGLE-AUTHENTICATOR
remote-cert-tls server	# USE-GOOGLE-AUTHENTICATOR
auth-nocache			# USE-GOOGLE-AUTHENTICATOR
auth-user-pass			# USE-GOOGLE-AUTHENTICATOR
EOF
	cat $temp > /etc/openvpn/server/client-common.txt

	cat << EOF 



Google Authenticator is now enabled for future clients. 

To disable Google Authenticator remove these lines from 
/etc/openvpn/server/client-common.txt:

reneg-sec 30000			# USE-GOOGLE-AUTHENTICATOR 
remote-cert-tls server	# USE-GOOGLE-AUTHENTICATOR
auth-nocache			# USE-GOOGLE-AUTHENTICATOR
auth-user-pass			# USE-GOOGLE-AUTHENTICATOR

EOF
}

#}}}

print_help() { #{{{
	cat << EOF
Options:
-l          list clients by date (ls /etc/openvpn/server/easy-rsa/pki/issued/)
-L          list clients by name
-a <name>   add client
-r <name>   revoke client
-g          install and enable Google Authenticator
-p          password for Google Authenticator
-v          be verbose
-h          this help

EOF
}

#}}}
# main {{{
	[ "X$SUDO_USER" != "X" ] && { OVUSER=$SUDO_USER; } || { OVUSER=$LOGNAME; }
	OVUSERHOME=$( eval echo ~$OVUSER );

	while getopts "lLa:r:gp:vh" opt; do
		case $opt in
			l) list date;;
			L) list alphabet;;
			a) ADDCLIENT=$OPTARG ;;
			r) revoke $OPTARG ;;
			g) install_google_authenticator; enable_google_authenticator ;;
			p) GPASSWORD=$OPTARG ;;
			v) VERBOSE=1 ;;
			h) print_help ;;
		esac
	done
	[ -n "$ADDCLIENT" ] && { 
		add $ADDCLIENT;
	}

#}}}
