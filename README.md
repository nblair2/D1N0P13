# D1N0P13 - A DNP3 Covert Channel

D1N0P13 (pronounced dino-pie) is a network storage covert channel that encodes inforrmation in legitimate DNP3[^dnp3] traffic.

Covert Channels have historically been confined to information technology (IT) systems and protocols. However, operational technology (OT) malware is becoming increasingly advanced. The recent discovery of INCONTROLLER / PIPEDREAM [^mandiant-incontroller] [^dragos-pipedream] malware illustrates a new tier of OT malware. OT has been difficult to secure due to the use of legacy systems and proprietary protocols. However, it is  necessary to begin the study of OT network protocols with the same rigor that IT network protocols have been subject to in order to prepare OT systems for the advanced tradecraft that adversaries are demonstrating.

## Channel

Currently D1N0P13 has three channels that operate at the DNP3 Application layer: IIN, Application Request, and Application Response. Other channels are possible in other fields of the Application Layer or the DNP3 Transport Layer.

### DNP3 Application

#### IIN | (Outstation -> Master) | 2b/fragment

The internal indication (IIN) field is a 16-bit field in application response headers that is used to communicate error conditions or states in the outstation to the master. IIN2.6 and IIN2.7 (the most significant two bits of the 16 IIN bits) are both reservered, and should be set to 0.

D1N0P13 takes advantage of these fields in order to transmit information. Because IIN fields only exist in application responses, this method can only be used to transmit information from outstation to master.

Because the bits are not used in standard DNP3 functioning, common protocol parsers such as WireShark[^wireshark] do not highlight when IIN2.6 and IIN2.7 are not set to 0.

*Note: the D1N0P13 server assumes all incoming frames have covert data encoded when using the IIN method. If a normal frame that was not modified by the D1N0P13 client is processed, the server will assume the IIN2.6 and IIN2.7 set to 0 to mean two 0 bits in the message string.

#### Application Request | (Master -> Outstation) | 2b/fragment

The application request function code is a 8-bit field in application request headers that is used to communicate the function of the message. Application request function codes are limited to 0x00 - 0x21, but can take on values between 0x00 - 0xFF.

D1N0P13 takes advantage of the unused bits in the application request function code to encode 2 additional bits of information, while retaining the original function code.

#### Application Response | (Outstation -> Master) | 4b/fragment *UNTESTED*

The application response function code is a 8-bit field in application response headers that is used to communicate the function of the message. Application response function codes are limited to 0x81 - 0x83, but can take on values between 0x00 - 0xFF.

D1N0P13 takes advantage of the unused bits in the application response function fields to encode 4 bits of information, while retaining the original function code.

### DNP3 Transport

Further research required.

### Additional Ideas for Channels

Some additional ideas for where a covert channel can be encoded:

* Additional reserved fields exist in the standard
* Add a custom DNP3 Application object

### Future Work

Right now D1N0P13 is a simple proof of concept that demonstrates that covert channels can be encoded into legitimate DNP3 traffic. Future ideas include:

* Find additional, higher bandwidth, channels
* Chain multiple channels together to achieve higher bandwidth
* Chain multiple channels together to achieve

## Docker Experiment Setup
A three-container docker-compose file is provided in order to test D1N0P13. It consists of a DNP3 master at `10.0.1.5` (or `master.docker`), a router with interfaces at `10.0.1.2` and `10.0.2.2`, and a DNP3 outstation at `10.0.2.10` (or `outstation.docker`).

1. Launch the docker containers with `docker-compose -f docker/docker-compose.yml`
2. Open a shell on each of the docker containers with `docker exec -it {master|outstation|router} /bin/bash`
3. Run the send or receive scripts with `/root/d1n0p13-{server|client}.py [-opts]`
4. In order to simulate DNP3 traffic between the outstation and master, use the provided DNP3 examples located at `/bin/master-demo` and `/bin/DNP3-outstation-demo`. Run `/bin/outstation-demo` in the outstation container and then `/bin/DNP3-master-demo outstation.docker` in the master container. *note that the outstation needs to be started before the master, and in this case `outstation.docker` is resolved to the IP of the outstation container*

## Citations

[^mandiant-incontroller]: [Mandiant - INCONTROLLER](https://www.mandiant.com/resources/blog/incontroller-state-sponsored-ics-tool)
[^dragos-pipedream]: [Dragos - PIPEDREAM](https://www.dragos.com/blog/industry-news/chernovite-pipedream-malware-targeting-industrial-control-systems/)
[^dnp3]: [DNP3](https://www.dnp.org/About/Overview-of-DNP3-Protocol)
[^wireshark]: [WireShark](https://www.wireshark.org/)
