#!/bin/bash
#title			:ip_check.sh
#description	:Check actual IP address and execute some action on change. Ip is store in a temporary file.
#author			:P.GINDRAUD
#author_contact	:pgindraud@gmail.com
#date			:2014-04-08
#usage			:./ip_check.sh
#usage_info		:
#options		:NONE
#notes			:
# [log system] add log entries in local syslog to inform about ip change, start, or error
# [mail system] send a mail when the ip have changed or when a incorrect ip looking is detected
# [dyn update system] send a query to update a ip address of a dyn dns host
#	[dns check system] verify that the actual ip address is the same that the dns server answer
#
#versions_notes	:
#	version 2.0
#				+adding dyndns ability
#	version 3.0
#				+refund all the check system
#				+adding syslog ability
#				+adding error mailing
#				+adding dns checking facility
#	version 3.1 : 2014-06-28
#				+fix some dependancies
#				+add documentations
#	version 3.2 : 2014-07-09
#				+fix some bug with wget lookup
#	version 3.3 : 2014-07-10
#				+fix some bug with dig lookup
#	version 3.4 : 2014-09-14
#				+fix empty dns string error
VERSION='3.4'
#==============================================================================
# url for ipv4 retrieving
IPV4_URL="http://bot.whatismyipaddress.com/"


# the directory that contains the script linked by this
ACTION_DIR='scripts/'

## LINKED SCRIPTS
# This script can be found at 
# https://github.com/Turgon37/DynUpdate/blob/master/dynupdate.sh
DYN_UPDATE_SCRIPT='dynupdate.sh'

## DYN DNS PARAMETERS
# remote server to which send dyn update string
DYNDNS_SERVER=''
# username use to make dyn update
DYNDNS_USERNAME=''
# dyn password associate to above username
DYNDNS_PASSWORD=''
# the dns hostname to update
DYNDNS_HOSTNAME='host.example.com'

## DNS LOOKUP PARAMETERS
# dns server to use for dns checking lookup
DNS_SERVER='8.8.8.8'
# hostname to lookup
DNS_HOSTNAME="$DYNDNS_HOSTNAME"

## MAIL PARAMETERS
EMAIL_TO="sysadmin@example.com"



#========== INTERNAL OPTIONS ==========#
USER_AGENT="ip_check/${VERSION}"

WGET_PATH=$(which wget 2>/dev/null)

GREP_PATH=$(which grep 2>/dev/null)
MAILX_PATH=$(which mailx 2>/dev/null)
TEMPFILE_PATH=$(which tempfile 2>/dev/null)
DIG_PATH=$(which dig 2>/dev/null)
LOGGER_PATH=$(which logger 2>/dev/null)

IPV4_FILE="/tmp/ipv4"
IPV4_REGEXP='([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}'



#========== INTERNAL VARIABLES ==========#
IS_DEBUG=0
IS_VERBOSE=0

IF_FORCE_UPDATE=0
IF_MAIL=1
IF_DNS_CHECK=1
IF_DYNDNS_UPDATE=1
IF_SYSLOG=1


# set on ipv4 mode all over the script
IF_IPV4=1


#========== INTERNAL FUNCTIONS ==========#
# Print help msg
function _usage() {
  echo -e "Usage : $0 [OPTION...]

Get actual ip address and compare it to the last registered.
If they differ do some action.

Options :
    --action-dir=DIRECTORY   set the directory which contains scripts that
                            are call by this script (default : '$ACTION_DIR')
    -f, --force        force an update as if the IP had changed
    -h, --help         Show this message
    --ipv4-file=FILE   specify a temporary file in which save ip address
                          (Default: ${IPV4_FILE})
    --ipv4-url=URL manually set the url use for ipv4 looking (default $IPV4_URL)
    -l, --log          append running statement to syslog (ON by default)
    -!l, --no-log      append running statement to syslog
    -m, --mail         enable notification by email (ON by default)
    -!m, --no-mail     disable mail notification
    --update-dyndns    unable dyndns update when IP change (ON by default)
    --no-update-dyndns disable dyndns update
    --check-dyndns     unable dns checking after dyndns ipdating when IP change (ON by default)
    --no-check-dyndns  disable dyndns checking
    -v, --verbose      show more running messages
    -vv, --debug       show debug messages"
}

# Print a msg to stdout if verbose option is set
# @param[string] : the msg to write in stdout
function _echo() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "$*"
  fi
}

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "Error : $*" 1>&2
  fi
}

# Print a msg to stdout if debug verbose is set
# @param[string] : the msg to write in stdout
function _debug() {
  if [[ $IS_DEBUG -eq 1 ]]; then
    echo -e "debug: $*"
  fi
}

# Print a msg to stderr and quit
function _errorq() {
  echo "$0: $1" 1>&2
  exit 2
}

# Print a msg to stderr with help suggest and quit
function _p_errorq() {
  echo "$0: $1" 1>&2
  echo "Try '$0 --help' for more information." 1>&2
  exit 2
}

# Retrieve a web page which contains the actual ipv4 address from internet
# param[in](string)	: the file path in which the web page will be store
# return	: 0 if the get query success
#			: all other value if not
# return(echo)	: the ip address if form of an string
# return	: set var result
function _get_ipv4() {
  # downloading the web page
  ${WGET_PATH} --quiet --timeout=10 --user-agent=${USER_AGENT} --output-document="$1" "$IPV4_URL"
  if [[ $? -ne 0 ]]; then
    _errorq 'error during ipv4 web page lookup, please check the connection or the url'
  fi

  result=$(${GREP_PATH} --extended-regexp --only-matching --max-count=1 "${IPV4_REGEXP}" "$1")
  if [[ $? -ne 0 || -z "$result" ]]; then
    rm --force "$1"
    _do_error "'$1' contains incorrect ipv4 address, value='$(cat "$1")' please check the connection or the url"
    _errorq "'$1' contains incorrect ipv4 address, value='$(cat "$1")' please check the connection or the url"
  fi

  rm --force "$1"
}

# Check the integrity of the temporary file localized in /tmp dir
# Verify that temporary files are readable and writable
function _check_ip_file() {
  if [[ -f ${IPV4_FILE} ]]; then
    if [[ ! -r ${IPV4_FILE} || ! -w ${IPV4_FILE} ]]; then
      _error 'ip database file is corrupt'
      _debug 'trying to delete them...'

      rm ${IPV4_FILE}
      if [[ $? -eq 0 ]]; then
        _debug 'success'
      else
        _debug 'error'
        _do_error "unable to access to ${IPV4_FILE} and unable to delete it"
      fi
    fi
  fi
}

# Check the world ipv4 and do update if change appears
# param[in](string)	: the string that correspond to current ipv4 address
# param[in](string)	: the string that contains the actual date for login
function _update_ipv4() {
  local current_ipv4="$1"
  local previous_ipv4=
  local current_date="$2"

  #file exist
  if [[ -f ${IPV4_FILE} ]]; then
    previous_ipv4=$(cat ${IPV4_FILE})

    #compare bot address
    _debug "previous IPv4 : ${previous_ipv4}"
    if [[ "${previous_ipv4}" != "${current_ipv4}" || "${IF_FORCE_UPDATE}" -eq 1 ]]; then
      _echo "${current_date} New IPv4 [${current_ipv4}]"
      _ipv4_to_file "${current_ipv4}"
      _do_update "${current_ipv4}" "${previous_ipv4}"
    else
      _echo "${current_date} IPv4 unchanged"
      _debug "nothing to do"
      _do_check "${current_ipv4}" "${previous_ipv4}"
    fi

  else
  #file not exist
    _echo "${current_date} Starting IPv4 [${current_ipv4}]"
    _ipv4_to_file "${current_ipv4}"
    _do_start "${current_ipv4}" "${previous_ipv4}"
  fi
}


function _ipv4_to_file() {
  echo "$1" > ${IPV4_FILE}
}


##### CALLING FUNCTION #####

# Call when the temporary file doesn't already exist
# Example : After the system boot
# param[in](string) : ipv4
# param[in](string) : previous (old) ipv4
function _do_start() {
  _debug '#do start'
  _sendmail_current_ip "$1"
  _update_dyndns "$1"
  _syslog "starting with ip $1"
}

# Call when the temporary file exist and an ip address had changed
# Example : After the connection restart
# param[in](string) : ipv4
# param[in](string) : previous (old) ipv4
function _do_update() {
  _debug '#do update'
  _sendmail_new_ip "$1"
  _update_dyndns "$1"
  _syslog "updating ip from '$2' (old) to '$1' (new)"
}

# Call just after a call to _do_start or _do_update function
# This can make some check operation to be sure that ip have been correctly set
# param[in](string) : ipv4
# param[in](string) : previous (old) ipv4
function _do_check() {
  _debug '#do check'
  _check_dyndns "$1"
}

# Call when an fatal error occur
# Example : When the temporary file not accessible
# param[in](string)	: the error message
function _do_error() {
  _debug '#do error'
  _error "error : $1"
  _sendmail_error "$1"
  _syslog "error appear : $1"
}

##### END CALLING FUNCTION #####



##### CALLED FUNCTION #####

# add syslog entry
# param[in](string)	: the string that will be logged
function _syslog() {
  if [ "${IF_SYSLOG}" -eq 0 ]; then return; fi

  _echo 'Syslogging'
  ${LOGGER_PATH} -t ${USER_AGENT} "$1"
}

# send a mail to inform that ip checking system have restart
# param[in](string)	: the string that correspond to the current ip address
function _sendmail_current_ip() {
  if [[ "${IF_MAIL}" -eq 0 ]]; then return; fi

  _echo 'Sending current IP by mail'
  _debug "send to ${EMAIL_TO}"
  (
  echo "$(hostname).$(domainname) IPv4 : $1"
  ) | ${MAILX_PATH} -s 'IP Check : Starting ip check' ${EMAIL_TO}
}

# send a mail to inform that ip have changed
# param[in](string)	: the string that correspond to the current ip address
function _sendmail_new_ip() {
  if [[ "${IF_MAIL}" -eq 0 ]]; then return; fi

  _echo 'Sending new IP by mail'
  _debug "send to ${EMAIL_TO}"
  (
  echo "$(hostname).$(domainname) IPv4 : $1"
  ) | ${MAILX_PATH} -s 'IP Check : Updating ip' ${EMAIL_TO}
}

# send a mail to inform about an error
# param[in](string)	: the string that describe the error
function _sendmail_error() {
  if [[ "${IF_MAIL}" -eq 0 ]]; then return; fi

  _echo 'Sending error informations by mail'
  _debug "send to ${EMAIL_TO}"
  (
  echo 'An error appear for this reason'
  echo "$1"
  ) | ${MAILX_PATH} -s 'IP Check : Error detected' ${EMAIL_TO}
}

# do a dyndns update for defined domain
# param[in](string)	: the string that correspond to the current ip address
function _update_dyndns() {
  local opts=

  if [[ $IF_DYNDNS_UPDATE -eq 0 ]]; then return; fi
  _echo 'Updating DynDns'
  _debug "update dyndns host : '${DYNDNS_HOSTNAME}' at '${DYNDNS_SERVER}'"

  if [[ $IS_VERBOSE -eq 0 ]]; then
    opts="$opts --no-output"
  fi

  ${ACTION_DIR}${DYN_UPDATE_SCRIPT} $opts -a "$1" -d "${DYNDNS_SERVER}" "${DYNDNS_USERNAME}" "${DYNDNS_PASSWORD}" "${DYNDNS_HOSTNAME}"
}

# make an dns query to be sure that the ip returned by ovh is true
# param[in](string)	: the string that correspond to the current ip address
function _check_dyndns() {
  local opts='+noall +answer'
  local dns_lookup=
  local dns_ip=

  if [[ "${IF_DNS_CHECK}" -eq 0 ]]; then return; fi
  _echo 'Checking DynDns'
  _debug "check dyndns host : '${DYNDNS_HOSTNAME}' with '${DNS_SERVER}'"
  dns_lookup=$(${DIG_PATH} $opts "@${DNS_SERVER}" "${DNS_HOSTNAME}")
  _debug "dns lookup result = '$dns_lookup'"
  if [ -z "$dns_lookup" ]; then
    _errorq 'error during dns hostname lookup'
  fi

  dns_ip=$(echo $dns_lookup | ${GREP_PATH} --extended-regexp --only-matching --max-count=1 "${IPV4_REGEXP}")
  if [[ "$?" -ne 0 ]]; then
    _errorq 'error during dns hostname finding'
  fi
  _debug "dns ip result = '$dns_ip'"

  if [[ -z "$dns_ip" ]]; then
    _do_error "error : dns lookup ip address is empty"
  elif [[ "$dns_ip" != "$1" ]]; then
    IS_DEBUG=1
    IS_VERBOSE=1
    _debug "dns lookup result = '$dns_lookup'"
    _debug 'turning on verbose'
    _debug "dns ip result = '$dns_ip'"
    _do_error "error : dns lookup ip address (='$dns_ip') dismatch with actual ip (='$1'), trying to reset it"
    _update_dyndns "$1"
  fi
}

##### END CALLED FUNCTION #####



#========== MAIN FUNCTION ==========#
# Main
# param	:same of the script
# return	:
function main() {
  ### VARIABLE DECLARATIONS
  # temporary file which contains the index web page
  local tmp_file=
  # store the current ipv4
  local current_ipv4=
  # store the current date string
  local current_date=

  ### PARAMETER PARSING
  for i in $(seq $(($#+1))); do
    #catch main arguments
    case $1 in
    --action-dir=*) ACTION_DIR=$(echo $1 | cut -d '=' -f 2-);;
    -f|--force-update) IF_FORCE_UPDATE=1;;
    --ipv4-file=*) IPV4_FILE=$(echo $1 | cut -d '=' -f 2-);;
    -h|--help) _usage; exit 0;;
    --ipv4-url=*) IPV4_URL=$(echo $1 | cut -d '=' -f 2-);;
    -l|--log) IF_SYSLOG=1;;
    -!l|--no-log) IF_SYSLOG=0;;
    -m|--mail) IF_MAIL=1;;
    -!m|--no-mail) IF_MAIL=0;;
    --update-dyndns) IF_DYNDNS_UPDATE=1;;
    --no-update-dyndns) IF_DYNDNS_UPDATE=0;;
    --check-dyndns) IF_DNS_CHECK=1;;
    --no-check-dyndns) IF_DNS_CHECK=0;;
    -v|--verbose) IS_VERBOSE=1;;
    -vv|--debug) IS_DEBUG=1;;
    -*) _p_errorq "invalid option -- '$1'";;
    esac
    shift
  done

  ### CORE VERIFICATION
  if [[ -z "$WGET_PATH" ]]; then
    _errorq "Wget not found, please install it or check your configuration"
  fi
  if [[ -z "$GREP_PATH" ]]; then
    _errorq "Grep not found, please install it or check your configuration"
  fi

  if [[ -z "${EMAIL_TO}" ]] || [[ -z "${MAILX_PATH}" ]]; then
    _debug 'No mailer specified or mailx command not available. The mailling system is disable'
    IF_MAIL=0
  fi
  if [[ ! -f "${ACTION_DIR}${DYN_UPDATE_SCRIPT}" ]] || [[ -z "$DYNDNS_SERVER" ]] || [[ -z "$DYNDNS_USERNAME" ]] || [[ -z "$DYNDNS_PASSWORD" ]] || [[ -z "$DYNDNS_HOSTNAME" ]]; then
    _debug 'Dyndns parameters not correctly specified or dyn script not reachable. The dyndns update system is disable'
    IF_DYNDNS_UPDATE=0
  fi
  if [[ -z "${DIG_PATH}" ]] || [[ -z "$DNS_SERVER" ]] || [[ -z "$DNS_HOSTNAME" ]]; then
    _debug 'Dns parameters not correctly specified or dig command not available. The dns check system is disable'
    IF_DNS_CHECK=0
  fi
  if [[ -z "${LOGGER_PATH}" ]] || [[ -z "${USER_AGENT}" ]]; then
    _debug 'User agent parameter not correctly specified or logger command not available. The syslog check system is disable'
    IF_SYSLOG=0
  fi

  if [[ -z "${TEMPFILE_PATH}" ]]; then
    _error "Tempfile command not found, using default temp filename"
    tmp_file='/tmp/ip_check.tmp'
  else
    tmp_file="$(tempfile)"
  fi

  # show verbose for option
  _debug "using ${IPV4_FILE} as IPv4 storage file"
  if [[ $IF_MAIL -eq 1 ]]; then _debug 'set option MAIL'; fi
  if [[ $IF_DYNDNS_UPDATE -eq 1 ]]; then _debug 'set option DYNDNS update'; fi
  if [[ $IF_DNS_CHECK -eq 1 ]]; then _debug 'set option DNS check'; fi
  if [[ $IF_SYSLOG -eq 1 ]]; then _debug 'set option LOG'; fi
  if [[ $IF_FORCE_UPDATE -eq 1 ]]; then _debug 'set option FORCE_UPDATE'; fi

  # get current date
  current_date=$(date +%Y-%m-%d_%T)
  _debug "set date to '${current_date}'"

  ## RETRIEVE IPv4 ADDRESS
  if [[ $IF_IPV4 -eq 1 ]] && [[ -n $IPV4_URL ]]; then
    _get_ipv4 "$tmp_file"
    current_ipv4="$result"
    _debug "set IPv4 to '${current_ipv4}'"

    # chech ip file integrity
    _check_ip_file

    # determine whether a ip update is needed
    _update_ipv4 "${current_ipv4}" "${current_date}"
  else
    _debug 'IPv4 mode disable or not configure'
  fi
}

main "$@"