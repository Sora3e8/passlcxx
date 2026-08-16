# PASSL - Paranoid SSL protocol

Definition
---------------------------------------------
 - Paranoid SSL (PASSL) protocol is a derivate of the regular SSL protocol
 - The fundamental difference lies in TLS handshake procedure and protocol application
 - PASSL does not use static private keys, because it's main focus is on trusted secure session
 - The PASSL tries to improve on the security of the session by utilizing bi-directional PUBKEY exchange
 - Both the server and client generate new PRIVKEYS each session and exchange PUBKEYS to ensure no part of the shared secret is readable  
 - Once the pubkey exchange is completed both parties exchange part of the shared secret which is then assembled on each side
 - Then communication proceeds using symmetric encryption like AES, etc...

Algorithm comparison
---------------------------------------------
## Paranoid TLS handshake
  ```
  Client [syn] --> server
  Client <--[syn-ack with SSL cert] server
  Client [syn-ack with SSL cert]--> server
  *client and server generate part of shared secret*
  Client <--[shared-secret 1/2] server
  Client [shared-secret 1/2]--> server
  *client and server assembles shared secret*
  Communication continues encrypted using shared secret
  ```

## Regular TLS handshake
  ```
  Client [syn] --> server
  Client <--[syn-ack with SSL cert+premaster secret] server
  Client [Premaster secret] --> server
  *Session keys are created*
  Communication continues encrypted using session keys
  ```

## PASSL packet structure

```
Header - 10bytes
  IDENTIFIER - 'PASSL' - 5bytes
  Type - 1byte [ 1 - pubkey, 2 - encrypted_data]
  CRC - 4bytes
Data header - 12bytes
  IDENTIFIER - 'DATA' - 4bytes
  SIZE - 4bytes
  CRC - 4bytes
Data chunk - variable size
CRC - 4bytes
```
