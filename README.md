## Crowdsec Fire_tool

A simple wrapper around the pkg/cticlient to generate IP's from firedatabase as newline delimeted file.

#### Go Install
```
go install "github.com/crowdsecurity/crowdsec-fire-tool"
```
Make sure "~/go/bin/" is within your $PATH

#### Manual Installation
```bash
git clone https://github.com/crowdsecurity/crowdsec-fire-tool
go build
chmod +x crowdsec-fire-tool
install -m 600 crowdsec-fire-tool /usr/bin/ 
```

Usage

```bash
sudo CROWDSEC_FIRE_CTI_KEY=XXXXXX -o /var/lib/crowdsec/data/fire.txt crowdsec-fire-tool
```

#### Environment

#### CROWDSEC_FIRE_CTI_KEY

This is CTI key generated from [console](https://app.crowdsec.net/cti)

#### CROWDSEC_FIRE_OUTPUT

This is the desired output folder

#### Arguments

`--cti-key`

This is CTI key generated from [console](https://app.crowdsec.net/cti)

`-o | --output`
This is the desired output location
