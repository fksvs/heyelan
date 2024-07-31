HEYELAN - Denial of Service Attack Testing Tool
======================================
**Heyelan** is a Denial of Service attack testing tool offering a rich variety of Layer 3, Layer 4, and Layer 7 attack types.

## Table of Contents
1. [Warning and Disclaimer](#warning-and-disclaimer)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Contributing](#contributing)
6. [License](#license)

## Warning and Disclaimer

**This DoS testing tool is for network testing and educational purposes only. Unauthorized use can be illegal and is strictly prohibited. The user is fully responsible for any misuse or harm caused. The developer is not liable for any misuse or damage. Use responsibly, ethically, and with proper authorization.**

## Features

- **Layer 3** attacks:
	* ICMP ping flood
- **Layer 4** attacks:
	* SYN flood
	* ACK flood
	* SYN-ACK flood
	* PSH-ACK flood
	* ACK-FIN flood
	* RST flood
	* TCP XMAS flood
	* TCP null flood
	* UDP flood
- **Layer 7** attacks (under development):
	* GET flood
	* POST flood
- IP address spoofing

## Installation

- Clone the repository from [GitHub][] or [GitLab][]:

```console
git clone https://github.com/fksvs/heyelan
git clone https://gitlab.com/fksvs/heyelan
```

- change directory to `heyelan`:

```console
cd heyelan/
```
- build the source:

```console
make
```

## Usage

```console
usage: ./heyelan [attack type] [options]

attack types:

	syn    : SYN flood attack
	ack    : ACK flood attack
	synack : SYN-ACK flood attack
	pshack : PSH-ACK flood attack
	ackfin : ACK-FIN flood attack
	rst    : RST flood attack
	xmas   : TCP XMAS flood attack
	null   : TCP NULL flood attack
	udp    : UDP flood attack
	get    : HTTP GET flood attack
	post   : HTTP POST flood attack
	ping   : ICMP ping flood attack

options:

	-t [target IP address] : target IP address to attack
	-p [target port]       : target port to attack
	-h                     : help message
```

### Example Usage

```console
./heyelan pshack -t <target address>
```

## Contributing

Pull requests are welcome. For bug fixes and small improvements, please submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is free software; you can redistribute it and/or modify it under the terms of the GPLv3 license. See [LICENSE][] for details.

[GitHub]: https://github.com/fksvs/heyelan
[GitLab]: https://gitlab.com/fksvs/heyelan
[LICENSE]: https://www.gnu.org/licenses/gpl-3.0.en.html
