This repo contains two enclaves (E<sub>a</sub> and E<sub>b</sub>) along with two untrusted apps A<sub>a</sub> and A<sub>b</sub>
where E<sub>a</sub> and E<sub>b</sub> are managed by A<sub>a</sub> and A<sub>b</sub> respectively.

The apps A<sub>a</sub> and A<sub>b</sub> act as the untrusted transport between the
two enclaves E<sub>a</sub> and E<sub>b</sub>. A<sub>a</sub> communicates the outcome of the challenges to the user.
The communication between A<sub>a</sub> and A<sub>b</sub> implemented using a named pipe.

The protocol between these two pairs of enclaves and applications can be described as:
<img src="https://github.com/IvanSobko/sgx-enclaves-protocol/blob/master/protocol-figure.png" width=50% height=50%>
