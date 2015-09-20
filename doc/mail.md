## This is the documentation for 'mail' extension

This extension provide a mail sending on IpCheck Events

This extension is loaded automatically when you put the section ```[extension.mail]``` in configuration file

Following the list of option available in configuration file

 * ```sender``` : the name/address of sender field into each mails
 * ```recipient``` : the mail addres to which each mail will be supplied
    (multiple mail allowed separated by colon ',')
 * ```tag``` : a string to put into bracket in the mail subject.
    This help you to identify a mail among several other
 * ```body``` : The template of the mail content. This string use string format
    tags. For example theses tag must be put into embrace to be replaced
    by dynamic content during execution :
    {message} will be replaced by a description of the recently happend event
 * ```server``` : the smtp server hostname or ip address
 * ```port``` : the smtp server port
 * ```auth``` : a boolean indicates if the smtp need authentication or not.
    If set to True the two next parameters must be filled
 * ```username``` : the smtp login username
 * ```password``` : the smtp login password
 * ```start_tls``` : a boolean that indicates to use or not STARTTLS
 * ```ssl``` : a boolean that describe the SSL option, if True, the connection between stmp client and the smtp server will be in SSL, if false, the connection will be not certified by SSL
 * ```info_mail``` : a boolean that indicates if the informations mails must be send