# D1N0P13 - A DNP3 Covert Channel

D1N0P13 is a network storage covert channel that encodes inforrmation in legitimate DNP3[^dnp3] traffic.

Covert Channels have historically been confined to information technology (IT) systems and protocols. However, operational technology (OT) malware is becoming increasingly advanced. The recent discovery of INCONTROLLER / PIPEDREAM [^mandiant-incontroller] [^dragos-pipedream] malware illustrates a new tier of OT malware. OT has been difficult to secure due to the use of legacy systems and proprietary protocols. However, it is  necessary to begin the study of OT network protocols with the same rigor that IT network protocols have been subject to in order to prepare OT systems for the advanced tradecraft that adversaries are demonstrating.

## Docker Experiment Setup
A three-container docker-compose file is provided in order to test D1N0P13. It consists of a DNP3 master at `10.0.1.5` (or `master.docker`), a router with interfaces at `10.0.1.2` and `10.0.2.2`, and a DNP3 outstation at `10.0.2.10` (or `outstation.docker`).

1. Launch the docker containers with `docker-compose -f docker/docker-compose.yml`
2. Open a shell on each of the docker containers with `docker exec -it {master|outstation|router} /bin/bash`
3. Run the send or receive scripts with `/root/d1n0p13-{server|client}.py [-opts]`
4. In order to simulate DNP3 traffic between the outstation and master, use the provided DNP3 examples located at `/bin/master-demo` and `/bin/DNP3-outstation-demo`. Run `/bin/outstation-demo` in the outstation container and then `/bin/DNP3-master-demo outstation.docker` in the master container. *note that the outstation needs to be started before the master, and in this case `outstation.docker` is resolved to the IP of the outstation container*

## Usage

*D1N0P13 is currently written in python, and unlikely to run on real OT assets*

### Client

```
usage: D1N0P13-client [-h] [-e ENCRYPTION] [-s SRC] [-d DST] [-p SPORT] [-P DPORT] message

Send information over a covert channel embedded in DNP3 messages

positional arguments:
  message               message to send

options:
  -h, --help            show this help message and exit
  -e ENCRYPTION, --encryption ENCRYPTION
                        Optional key to enable stream cipher (default: None)
  -s SRC, --src SRC, --source SRC
                        source to send from (default: None)
  -d DST, --dst DST, --destination DST
                        destination to send to (default: None)
  -p SPORT, --sport SPORT
                        source port (default: None)
  -P DPORT, --dport DPORT
                        destination port (default: None)
```

### Server

```
usage: D1N0P13-server [-h] [-e ENCRYPTION] [-s SRC] [-d DST] [-p SPORT] [-P DPORT]

Recieve information over a covert channel embedded in DNP3 messages

options:
  -h, --help            show this help message and exit
  -e ENCRYPTION, --encryption ENCRYPTION
                        Optional key to enable stream cipher (default: None)
  -s SRC, --src SRC, --source SRC
                        source to recieve from (default: None)
  -d DST, --dst DST, --destination DST
                        destination to filter for (default: None)
  -p SPORT, --sport SPORT
                        source port (default: None)
  -P DPORT, --dport DPORT
                        destination port (default: None)
```
## Channel

Currently D1N0P13 has two channels that operate at the DNP3 Application layer: IIN and CRC. However, other channels are certainly possible in other fields of the Application Layer or the DNP3 Transport Layer.

### DNP3 Application

#### IIN

The internal indication (IIN) field is a 16-bit field in application response headers that is used to communicate error conditions or states in the outstation to the master. IIN2.6 and IIN2.7 (the most significant two bits of the 16 IIN bits) are both reservered, and should be set to 0.

D1N0P13 takes advantage of these fields in order to transmit information. Because IIN fields only exist in application responses, this method can only be used to transmit information from outstation to master.

Because the bits are not used in standard DNP3 functioning, common protocol parsers such as WireShark[^wireshark] do not highlight when IIN2.6 and IIN2.7 are not set to 0.

### DNP3 Transport

Further research required.

### Additional Ideas

Some additional ideas for where a covert channel can be encoded:

* Numeros additional reserved fields exist, and can be used to transmit information
* the number of DNP3 Application Response Objects could be manipulated

## Citations

[^mandiant-incontroller]: [Mandiant - INCONTROLLER](https://www.mandiant.com/resources/blog/incontroller-state-sponsored-ics-tool)
[^dragos-pipedream]: [Dragos - PIPEDREAM](https://www.dragos.com/blog/industry-news/chernovite-pipedream-malware-targeting-industrial-control-systems/)
[^dnp3]: [DNP3](https://www.dnp.org/About/Overview-of-DNP3-Protocol)
[^wireshark]: [WireShark](https://www.wireshark.org/)
