## This is the documentation for 'command' extension

This extension provide a command execution on IpCheck Events
This extension is loaded automatically when you put the section ```[extension.command]``` in configuration file

Following the list of option available in configuration file

The configuration take theses options :
 * ```exec``` the name/path of the command to run.
    The command is searched in system's PATH, then in resources/ directory
    You have to put specific commands/script into the resources/ directory
 * ```args``` the argument to pass to the command during
In this string you can put some replacement tokens that will be replaced by their value before command execution. You have to put these tokens into brackets {token}, then the text into the brackets and the brackets themselves are being replaced during command execution
    * {ip} will be replaced with ip address value of current ip address

 * ```event``` the name list of event when the command will be executed
event can be :
    * *E_BEFORE_CHECK*  empty event for trigge before update
    * *E_AFTER_CHECK*  empty event for trigger after update
    * *E_START*  it's the first time the script is run
    * *E_UPDATE*  the Ip address value have changed
    * *E_NOUPDATE*  Nothing update
    * *E_ERROR*  an error appear see type for detail
