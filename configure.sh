#!/bin/bash
#title			  :configure.sh
#description$ :Run a configuration menu to help the user to setup Ipcheck
#author			  :P.GINDRAUD
#author_contact :pgindraud@gmail.com
#date			    :2014-04-08
#usage			  :./ip_check.sh
#usage_info		:
#options		  :NONE
#notes			  :

if [ ! -d 'ipcheckadvanced' ]; then
  echo "This script must be run at the root of IpCheck folder" 1>&2
  exit 1
fi

echo '    [ MENU ]'
echo ' 1) Configure for DYN UPDATE usage'
echo ' '
echo ' '
echo ' q) Quit'
echo 'Press a number'
choice=0
while [[ $choice -lt 1 || $choice -gt 1 ]]; do
  read -n 1 choice
  if [[ $choice = 'q' || $choice = 'Q' ]]; then exit 0; fi
done

echo -e '\n\n'
case $choice in
  1)
    echo ' => Downloading the dynupdate script from github'
    wget -O ipcheckadvanced/resources/dynupdate.py -q https://raw.githubusercontent.com/Turgon37/DynUpdate/master/dynupdate.py || exit 1
    chmod +x ipcheckadvanced/resources/dynupdate.py
    echo -e ' => Copy IpCheck configuration to \e[33m config_user.conf \e[0m'
    cp -i config.conf config_user.conf || exit 1
    read -p 'Enter the server of your dynhost : ' server
    read -p 'Enter the hostname of your dynhost : ' hostname
    read -p 'Enter the username that is allowed to perform update : ' username
    read -p 'Enter the password associated the above username : ' password
    echo "

[extension.digchecker]
server = 8.8.8.8
hostname = $hostname

[extension.command]
exec = dynupdate.py
args = -a {ip} --no-output -s $server -h $hostname -u $username -p $password
event = E_START, E_UPDATE
" >> config_user.conf
    echo "Add this line to your crontab to execute this script at 5 minutes (recommanded) interval"
    echo ''
    echo "*/5 * * * * $(pwd)/ipcheck.py --no-output --config=$(pwd)/config_user.conf"
    echo ''
    echo "Don't forget to reduce the TTL of your DNS zone if you want your change to be applied fastly"
  ;;
esac
