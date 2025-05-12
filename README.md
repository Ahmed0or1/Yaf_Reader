```

 ___ ___         ___    ______                 __             
|   |   |.---.-.'  _|  |   __ \.-----.---.-.--|  |.-----.----.
 \     / |  _  |   _|  |      <|  -__|  _  |  _  ||  -__|   _|
  |___|  |___._|__|____|___|__||_____|___._|_____||_____|__|  
                 |______|                                     

```

# yaf_Reader

**yaf_Reader** is a Python tool that analyzes network flow records generated from `.yaf` files using `yafscii`.


## Requirements
- Python 3
- `yafscii` tool (install via: `sudo apt install yaf`)

https://tools.netsa.cert.org/yaf/install.html

## Usage

```bash
python main.py flows.yaf
```

> Make sure a matching `.yaf.txt` file exists or is generated for top-5 summary analysis.

## Example Output

```
Found 64 flows

192.168.1.5:443 -> 8.8.8.8:53
...

Top 5 Source Addresses:
192.168.1.5: 50 flows
...

Top 5 Destination Ports:
443: 40 flows
...
```

