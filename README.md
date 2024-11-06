# TU Delft Exam Auto-Enrollment Tool

## Authenticate SSO and get JWT for my.tudelft.nl

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

Use header `Authorization: Bearer <access_token>` for all sensitive requests
*Is `INGRESSCOOKIE` required??*

## URL Endpoints

Requires HTTP header `Authorization: Bearer <access_token>`

- List of registered courses: \
**GET** `https://my.tudelft.nl/student/osiris/student/inschrijvingen/cursussen?toon_historie=N&limit=25`
```json
{
  "items": [
    {
      "id_cursus_blok": 182940,
      "id_cursus": 116283,
      "studentnummer": "<studentnummer>",
      "cursus": "CSE2310",
      "collegejaar": 2024,
      "blok": "2",
      "periode_omschrijving": "Blok 2",
      "cursus_korte_naam": "Algorithm Design",
      "onderwijsvorm_omschrijving": null,
      "opmerking_cursus": null,
      "opmerking_cursus_blok": null,
      "punten": 5,
      "punteneenheid": "EC",
      "coordinerend_onderdeel_oms": "EWI algemeen",
      "faculteit_naam": "Elektrotechniek, Wiskunde en Informatica",
      "categorie_omschrijving": "Bachelor vak",
      "cursustype_omschrijving": "Cursus",
      "locatie": null,
      "periode_start_einddatum": "11-11-24 t/m 09-02-25",
      "timeslots": null,
      "onderdeel_van": "Verplichte vakken",
      "mag_uitschrijven": "J",
      "mag_voorzieningen_wijzigen": "N",
      "nieuw": "N",
      "historie": "N"
    },
	...
  ],
  "hasMore": false,
  "limit": 25,
  "offset": 0,
  "count": 7
}
```
- List of registered exams \
**GET** `https://my.tudelft.nl/student/osiris/student/inschrijvingen/toetsen?toon_historie=N&limit=25`
```json
{
  "items": [
    {
      "id_toets_gelegenheid": 694296,
      "id_cursus": 116288,
      "studentnummer": "<studentnummer>",
      "cursus": "CSE2510",
      "collegejaar": 2024,
      "cursus_korte_naam": "Machine Learning",
      "opmerking_cursus": null,
      "coordinerend_onderdeel_oms": "EWI algemeen",
      "faculteit_naam": "Elektrotechniek, Wiskunde en Informatica",
      "categorie_omschrijving": "Bachelor vak",
      "cursustype_omschrijving": "Cursus",
      "onderdeel_van": "Verplichte vakken",
      "toets": "TOETS-01",
      "toets_omschrijving": "Endterm (Weblab)",
      "toetsvorm_omschrijving": null,
      "onderwijsvorm_omschrijving": null,
      "opmerking_cursus_toets": null,
      "blok": "1",
      "periode_omschrijving": "Blok 1",
      "gelegenheid": 1,
      "toetsdatum": "2024-11-07T23:00:00Z",
      "dag": "Vrijdag",
      "tijd_vanaf": 13.3,
      "tijd_tm": 16.3,
      "locatie": "Drebbelweg, DW-HALL 1",
      "locatie_x": null,
      "locatie_y": null,
      "mag_uitschrijven": "N",
      "mag_voorzieningen_wijzigen": "N",
      "nieuw": "N",
      "resultaat": null,
      "historie": "N"
    },
	...
  ],
  "hasMore": false,
  "limit": 25,
  "offset": 0,
  "count": 1
}
```

- Details about tests for courses \
**GET** `https://my.tudelft.nl/student/osiris/student/cursussen_voor_toetsinschrijving/<id_cursus>`

```json
{
    "id_cursus": 116283,
    "studentnummer": <studentnummer>,
    "cursus": "CSE2310",
    "collegejaar": 2024,
    "cursus_korte_naam": "Algorithm Design",
    "opmerking_cursus": "",
    "punten": 5,
    "punteneenheid": "EC",
    "coordinerend_onderdeel_oms": "EWI general",
    "faculteit_naam": "Electrical Engineering, Mathematics and Computer Science",
    "categorie_omschrijving": "Bachelor Course",
    "cursustype_omschrijving": "Course",
    "onderdeel_van": "Compulsory Courses",
    "toetsen": [
        {
            "id_cursus": 116283,
            "id_toets_gelegenheid": 685890,
            "toets": "TOETS-01",
            "toets_omschrijving": "Written midterm",
            "toetsvorm_omschrijving": "",
            "opmerking_cursus_toets": "",
            "aanvangsblok": "2",
            "onderwijsvorm": "V",
            "onderwijsvorm_omschrijving": "",
            "blok": "2",
            "periode_omschrijving": "Block 2",
            "gelegenheid": 1,
            "beschikbare_plekken": null,
            "toetsdatum": "2024-12-08T23:00:00Z",
            "dag": "Monday",
            "tijd_vanaf": 13.3,
            "tijd_tm": 15,
            "locatie": "",
            "locatie_x": "",
            "locatie_y": "",
            "eerder_voldoende_behaald": "N",
            "voorzieningen": []
        }
    ]
}
```
*or*
```json
{
    "result": "FAILED",
    "failure": {
        "message": "Er is een fout opgetreden tijdens het aanroepen van de OSIRIS database",
        "code": 404,
        "detail": ""
    }
}
```

- Register for an exam \
**POST** `https://my.tudelft.nl/student/osiris/student/inschrijvingen/toetsen/` \
Body:
```json
{
  "toetsen": [
    {
      "voorzieningen": [],
      "id_cursus": 116283,
      "id_toets_gelegenheid": 685890,
      "toets": "TOETS-01",
      "toets_omschrijving": "Written midterm",
      "toetsvorm_omschrijving": "",
      "opmerking_cursus_toets": "",
      "aanvangsblok": "2",
      "onderwijsvorm": "V",
      "onderwijsvorm_omschrijving": "",
      "blok": "2",
      "periode_omschrijving": "Block 2",
      "gelegenheid": 1,
      "beschikbare_plekken": null,
      "toetsdatum": "2024-12-08T23:00:00Z",
      "dag": "Monday",
      "tijd_vanaf": "13:30",
      "tijd_tm": "15:00",
      "locatie": "",
      "locatie_x": "",
      "locatie_y": "",
      "eerder_voldoende_behaald": "N",
      "renderIndex": 0
    }
  ]
}
```
Response:
```json
{
	"statusmeldingen":[]
}
```
*or*
```json
{
    "statusmeldingen": [
        {
            "code": 1005,
            "tekst": "Geen toetsen geselecteerd.",
            "kolom": "TOETS",
            "type": "E"
        }
    ]
}
```