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
sudo CTI_API_KEY=XXXXXX OUTPUT_DIR=/var/lib/crowdsec/data/ crowdsec-fire-tool
```

Environment

#### CTI_API_KEY

This is CTI key generated from [console](https://app.crowdsec.net/cti)

#### OUTPUT_DIR

This is the desired output folder (Once completed there will be a file named `fire.txt` within)
