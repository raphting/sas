MA-3 and Vaudenay SAS protocol
==============================

The SAS protocol establishes peer-to-peer authenticated communication over an insecure channel by using an extra
channel, such as in Apple iMessage (see Application below).

This is a toy implementation of
the [Vaudenay SAS protocol [PDF]](https://www.iacr.org/archive/crypto2005/36210303/36210303.pdf).

To avoid 4 round-trips whereas 3 are sufficient, SAS was improved by
the [MA-3 protocol [PDF]](https://eprint.iacr.org/2005/424.pdf).

The used commitment scheme is an idealized commitment model in which a trusted third party reveals the commitment.
In a real world implementation, commitment schemes that don't require a trusted third party would be more practical (
random oracle, CRS model).

Application
-----------

Apple uses the SAS protocol
for [iMessage Contact Key Verification](https://security.apple.com/blog/imessage-contact-key-verification/), introduced
in iOS 17.2.
