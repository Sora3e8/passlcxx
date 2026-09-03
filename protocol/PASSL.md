# PASSL - Paranoid SSL protocol

Definition
---------------------------------------------
 - Paranoid SSL (PASSL) protocol is an ISO/OSI layer 5/6 protocol, derived from the SSL/TLS protocol.
 - As PASSL is also an ISO/OSI layer 5 protocol as well it controls lifetime of the session and controls validity of the exchange.
 - PASSL does not use static private keys, because it's main focus is on trusted session not identity verification. 
 - The PASSL tries to improve on the security of the session by utilizing bi-directional PUBKEY exchange. 
 - Both the server and client generate new PRIVKEYS each session and exchange PUBKEYS to ensure no part of the shared secret is readable  
 - Once the pubkey exchange is completed both parties exchange part of the shared secret which is then assembled on each side
 - Then communication proceeds using symmetric encryption like AES, etc...

Algorithm comparison
---------------------------------------------
## Paranoid TLS handshake
  ```
  Client [syn] --> server
  Client <--[syn-ack] server
  Client [pubkey]--> server
  Client <--[pubkey] server
  *client and server generate part of shared secret*
  Client <--[shared-secret 1/2] server
  Client [shared-secret 1/2]--> server
  *client and server assembles shared secret*
  Communication continues encrypted using shared secret
  ```

Scope and limitations
---------------------------------------------
- PASSL protocol is not meant for use outside of LAN.
- This protocol is meant to provide better protection than unencrypted LAN tcp/ip as session hijack would 
  require knowledge of both client and serveside as well as exact time window of an exchange.
- This protocol does not verify identity of the client/server as without 3rd party verification
  there's a risk of MITM attack thus it should not be used outside of LAN.

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
Protocol chunk - 10bytes
  IDENTIFIER - 'PASSL' - 5bytes
  Type - 1byte [ 1 - pubkey, 2 - encrypted_data]
  CRC - 4bytes
Data chunk - 16bytes
  IDENTIFIER - 'DATA' - 4bytes
  PAYLOAD_SIZE - 4bytes
  BLOCK_SIZE - 4bytes
  CRC - 4bytes
Data blocks - variable size
CRC - 4bytes
```

## Data chunk structure
```
CRC - 4bytes
DATA - arbitrary length given in BLOCK_SIZE
```
