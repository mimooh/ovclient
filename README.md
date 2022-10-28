ovclient.sh is a client for https://github.com/Nyr/openvpn-install (an easy and interactive openvpn SERVER installer) -- you must first install that and only then use ovclient.sh

ovclient.sh features:
* non-interactive client maker 
* optional google authenticator support
* only tested under ubuntu

example:
for i in adam matt steven; do
	sudo bash ovclient.sh -a $i; 
done
