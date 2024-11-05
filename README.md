# TU Delft Exam Auto-Enrollment Tool

## Steps to get JWT for my.tudelft.nl

1. **GET** `https://osi-auth-server-prd2.osiris-link.nl/oauth/authorize?response_type=code&client_id=osiris-authorization-server-tudprd&redirect_uri=https://my.tudelft.nl` Referrer: `https://my.tudelft.nl/`
	- Receive 🍪 `INGRESSCOOKIE` `JSESSIONID`
	- Save redirect `location`
2. **GET** `location` (from previous step 1)
	- With URL parameters `SigAlg` `Signature` `SAMLRequest` `RelayState`
	- Receive 🍪`TU-IDP-PHPSessionID`
	- Save AuthState from HTML `<input type="hidden" name="AuthState" value="_7bdc38df278ca50c8e2aaa8646757cfe9a1ff49e78:https://login.tudelft.nl/sso/saml2/idp/SSOService.php?spentityid=http%3A%2F%2Fnl.caci.osiris%2Fosiris-student&amp;RelayState=https%3A%2F%2Fosi-auth-server-prd2.osiris-link.nl%2Fsamlagent%2Fendpoint%3BOSIRIS-STUDENT&amp;cookieTime=1730838590"/>`
3. **GET** `https://login.tudelft.nl/sso/module.php/core/loginuserpass.php?AuthState=<AuthState>` (AuthState from step 3)
	- Include 🍪 `TU-IDP-PHPSessionID`
4. **POST** `https://login.tudelft.nl/sso/module.php/core/loginuserpass.php`
	- Include `x-www-form-urlencoded` consisting of `username`, `password` and `AuthState`
	- Include 🍪`TU-IDP-PHPSessionID`
	- Receive 🍪`language` and `TU-IDP-AuthToken`
	- Click the form in the HTML *or* save `SAMLResponse` and `RelayState`
5. **POST** `https://osilogin.tudelft.nl/osirissaml/saml2/acs/osiris-student`
	- Include `x-www-form-urlencoded` consisting of `SAMLResponse` and `RelayState`
	- *No need to include cookies (I'm guessing)*
	- Receive 🍪 `SAMLSESSIONID`
	- Save redirect `location`
6. **GET** `location` (from previous step 5)
	- Include 🍪`INGRESSCOOKIE` and `JSESSIONID`
	- Save code form redirect `location` (https://my.tudelft.nl#code=LXDfqM)
7. **GET** `https://my.tudelft.nl/` (*idk whether this shitty step is required, replicate and test*)
8. **POST** `https://my.tudelft.nl/student/osiris/token`
	- Include `JSON` body `{"code":"LXDfqM","redirect_uri":""}` with appropriate code from step 6
	- 💫💫Receive 🍪`INGRESSCOOKIE` 💫💫
	- 💫💫Receive 🖇️ JWT Token 🖇️ as `JSON` body `access_token` (*along with `token_type` and `scope`*) 💫💫

### Use header `Authorization: Bearer <access_token>` for all sensitive requests
*Is `INGRESSCOOKIE` required??*
