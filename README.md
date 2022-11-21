This repo contains two enclaves (E<sub>a</sub> and E<sub>b</sub>) along with two untrusted apps A<sub>a</sub> and A<sub>b</sub>
where E<sub>a</sub> and E<sub>b</sub> are managed by A<sub>a</sub> and A<sub>b</sub> respectively.

The apps A<sub>a</sub> and A<sub>b</sub> act as the untrusted transport between the
two enclaves E<sub>a</sub> and E<sub>b</sub>. A<sub>a</sub> communicates the outcome of the challenges to the user.
The communication between A<sub>a</sub> and A<sub>b</sub> implemented using a named pipe.

The protocol between these two pairs of enclaves and applications can be described as:

<img src="https://github.com/IvanSobko/sgx-enclaves-protocol/blob/master/protocol-figure.png" width=50% height=50%>

The code is annotated in folowing keypoints:

1. Points of communication between A<sub>a</sub> and A<sub>b</sub>: Sending and receiving the public keys,
the encrypted PSK, and the encrypted challenges/responses.
2. The points where the enclaves E<sub>a</sub> and E<sub>b</sub> generate their key pairs.
3. The points where the enclaves E<sub>a</sub> and E<sub>b</sub> calculate the shared secret.
4. The point where enclave E<sub>a</sub> generates and encrypts the challenge.
5. The point where enclave E<sub>a</sub> decrypts and verifies the response.
6. The point where enclave E<sub>b</sub> decrypts the challenge.
7. The point where enclave E<sub>b</sub> computes and encrypts the response.

Using the following format:
```
/***********************************************
 * 1. BEGIN: Enclave A: send public key to B and receive key from B
***********************************************/
<code here>
/***********************************************
 * 1. END: Enclave A: send public key to B and receive key from B
 ***********************************************/
 ```

  
  This repo was done in context of System Security course assignment at ETH Zurich.
