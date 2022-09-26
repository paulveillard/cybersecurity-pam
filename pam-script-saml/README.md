# pam-script-saml

This is a PAM module (using pam_script) which validates SAML assertions given as password. It is inspired by crudesaml, but implemented in PHP using LightSAML Core library.

Currently (and probably definately) only the `auth` PAM type is supported. For all other types you usually want to use another module (in the simplest case e.g. `pam_permit.so`).

License: [BSD 2-Clause](LICENSE)

Inspired by [crudesaml](https://ftp.espci.fr/pub/crudesaml/), but doesn't depend on (a patched) liblasso3.

## Key features
* Verification of SAML2 assertions as password replacement
* configuration options similar to crudesaml

## Compatibility
Integrates well with [SOGo Groupware](https://sogo.nu/) and the [Dovecot MDA](http://dovecot.org/) using PAM authentication.

## Configuration options
Passed in the PAM configuration in the format `key=value` (analog to crudesaml).

* `userid`: name of SAML attribute which contains the username. The value will be matched against the username passed by PAM. Default: `uid`
* `grace`: Time frame (in seconds) allowing the validation of the assertion deviating from the given time frame in the assertion (for clock skew or longer authentication validity). Default: `600`
* `saml_check_timeframe`: If `0` (disabled), validates the assertion also when it's expired. Default: `1`
* `idp`: Path to metadata file from which IdP certificates for assertion signature validation are extracted (multiple allowed). Signature is not verified, if none is given (not recommended!).
* `trusted_sp`: EntityID of SP which should be trusted (i.e. which is in the Audience {Assertion/Conditions/AudienceRestriction/Audience}). All are allowed, if none is given (not recommended!).
* `only_from`: Comma-separated list of IPs which can authenticate.

Logging can be enabled by using the `pam_script_auth` wrapper script and setting the `LOGFILE` variable. This helps troubleshooting a lot, since pam-script-saml is indicating where the validation fails.

## Installation
1. Download:
	1. Clone via git: `git clone https://github.com/ck-ws/pam-script-saml.git`
	2. Zipball: `https://github.com/ck-ws/pam-script-saml/archive/master.zip`
2. Install dependencies: `composer.phar install`
3. Make sure the following PHP extensions are installed: dom, mbstring, mcrypt, opcache (zend_extension)
4. Configure (see below)

## Configuration
1. Install [pam_script](https://github.com/jeroennijhof/pam_script) from source or from your distribution.
2. Install `pam-script-saml` in a directory of your choice (see above).
3. Use the given `pam_script_auth` file (or create a symlink from `pam_script_auth` to `pam-script-saml.php`)
4. configure the PAM module in `/etc/pam.d/` like this, for example:
````
auth	required	pam_script.so dir=<dir> userid=mail grace=900 [...]
account	required	pam_permit.so
session	required	pam_permit.so
````
