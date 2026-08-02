# PHPGurukul Small CRM - Insecure Deserialization (PHP Object Injection)

**CVE: pending (submitted to VulDB)**

**Affected:** PHPGurukul Small CRM v3.0 - v4.0

**Vendor:** https://phpgurukul.com/small-crm-php/

**Weakness:** CWE-502 Deserialization of Untrusted Data

## Summary

The login success handler of `/crm/login.php` performs a server-side request to
the third-party geolocation service over **plaintext HTTP** and passes the
unvalidated response directly to `unserialize()` without restricting
`allowed_classes`. Any on-path attacker (ARP spoofing, DNS cache poisoning,
malicious hosting provider) can intercept or replace that response with a
crafted serialized payload, which the server then deserializes. This leads to
PHP Object Injection and, when a usable gadget chain exists, arbitrary code
execution under the web server account.

## Vulnerable code

`crm/login.php` (lines 18-22), executed on every successful login:

```php
$ip_address = $_SERVER['REMOTE_ADDR'];
$geopluginURL = 'http://www.geoplugin.net/php.gp?ip=' . $ip_address;   // (1) plaintext HTTP
$addrDetailsArr = unserialize(file_get_contents($geopluginURL));        // (2) CWE-502
$city = $addrDetailsArr['geoplugin_city'];
$country = $addrDetailsArr['geoplugin_countryName'];
```

Issue (1): the request uses `http://` instead of `https://`, so the channel is
unencrypted and modifiable in transit.

Issue (2): `unserialize()` is called on data returned by a third-party network
service without `array('allowed_classes' => false)`, allowing instantiation of
arbitrary objects from the attacker-controlled stream.

## Proof of Concept

Attack preconditions:

1. Attacker can control the network path between the CRM server and
   `www.geoplugin.net` (MITM), e.g.:
   - ARP spoofing on the same LAN,
   - DNS cache poisoning, or
   - pointing the service host at an attacker-controlled host via the CRM
     server's `hosts` file (local demo).
2. Attacker has valid CRM credentials (or obtains them; credentials are stored
   in plaintext in the database).

Steps:

1. Start the malicious geolocation server:

   ```
   python exploit.py --port 80
   ```

   It answers every request with a crafted serialized payload
   (`payload.ser`).

2. Redirect `www.geoplugin.net` to the attacker host (hosts file / ARP / DNS).

3. Log in to the CRM with valid credentials.

4. On `login.php` the application deserializes the attacker-controlled
   response (line 20):

   ```php
   $addrDetailsArr = unserialize(file_get_contents($geopluginURL));
   ```

The serialized payload is a PHP object of the attacker's choosing:

```
O:8:"GadgetClass":1:{s:4:"prop";s:3:"val";}
```

With a POP/gadget chain present in the application or its bundled libraries,
this escalates to arbitrary code execution.

## Impact

- PHP Object Injection / potential remote code execution (conditional on
  gadget chain availability).
- Arbitrary object instantiation, unexpected application behaviour.
- Client IP transmitted in cleartext to a third-party service.

## Remediation

```php
$geopluginURL = 'https://www.geoplugin.net/json.gp?ip=' . $ip_address;
$addrDetails  = json_decode(file_get_contents($geopluginURL), true);
```

- Use the HTTPS JSON endpoint and parse with `json_decode()`.
- If `unserialize()` must be used, always pass `['allowed_classes' => false]`.

## References

- https://securized.dev/geoplugin-insecure-unserialize/
- https://cwe.mitre.org/data/definitions/502.html
- https://www.geoplugin.com/examples

## Disclaimer

This PoC is provided for security research and authorized testing only.
Do not use against systems you do not own or have explicit permission to test.
