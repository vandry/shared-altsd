ALTS
====

Application Layer Transport Security,
[ALTS](https://cloud.google.com/docs/security/encryption-in-transit/application-layer-transport-security),
is a protocol for implementing a peer authentication and transport layer
security handshake in gRPC as an external microservice. To secure a
subject channel, a gRPC client and server each contact their local ALTS
server (over a local channel that does not need transport layer security)
and relay the handshake exchange between the subject channel and the
ALTS server. The bytes of the handshake exchange remain opaque to the
gRPC client and server but at the end of it the ALTS server tells its
client the verified identity of the remote peer and gives it the
symmetric session key that was negociated. After that, the ALTS server
is disengaged and the gRPC client and server talk directly, encrypting
using the session key.

shared-altsd
============

shared-altsd is an ALTS server designed to be run on a loose network of
machines which can cross-verify each other's X.509 certificate and where
each machine has several user accounts each representing a different
identity (and user-foo@machine_a is not the same as user-foo@machine_b).
shared-altsd runs as a machine-global daemon with a machine-global
keypair and certificate, saving key management from having to be done
for each individual user account.

The protocol between shared-altsd and other instances of itself is
ad-hoc and private, so shared-altsd can only talk to other instances of
itself. Therefore, gRPC clients using ALTS with shared-altsd can only
open channels to gRPC servers also using ALTS with shared-altsd, not
with a different ALTS server.

gRPC clients and servers connect to their local shared-altsd using a
UNIX domain socket, by means of which shared-altsd knows the uid of the
account it is acting for. It will cryptographically attest to the remote
shared-altsd that the local identity is the corresponding username.

How to use
==========

The stock gRPC client libraries do not support connecting to an
ALTS server over UDS, requiring https://github.com/grpc/grpc/pull/31867
and other forthcoming patches.

Run the ALTS server:

```
$ cargo run /var/run/shared-alts/socket key_and_cert_in_same_file.pem
```

Usage in gRPC clients and servers in Python (needs patches):

```
credentials = grpc.alts_channel_credentials(
    None, 'unix:///var/run/shared-alts/socket', True)

# client
channel = grpc.secure_channel('host:port', credentials)

# server
server.add_secure_port('[::]:port', credentials)

class GreeterServer(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        peer = context.auth_context()['service_account'][0].decode()
```

Installation
============

It is recommended to run shared-altsd under a dedicated user account.
The daemon needs only access to its private key and certificate, and
write access to the directory in which the listening socket will be
created. No other account should be allowed to write the listening
socket directory, ensuring that ALTS clients know they are connecting
to the genuine local ALTS server.

A script scripts/generate_rotate_shared_alts_key is provided which is
intended to be run ~daily from cron. Because the script needs permission
(in the form of a secret key for dynamic DNS updates) to create TLSA
records in DNS that authorise new X.509 certificates for shared-altsd
in perpetuity, this should be run from a different more privileged
account, currently assumed to be root, but easily adaptable to do
something else such as running on an offline remote machine or perhaps
use an HSM.
