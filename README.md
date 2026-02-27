# ꓘamerka Plus GUI

## Ultimate Internet of Things/Industrial Control Systems reconnaissance tool. Upgraded Edition.

<p align="center"><img src="https://www.offensiveosint.io/content/images/2020/07/OffensiveOsint-logo-RGB-2.png" alt="logo" width="200"/></p>

### Powered by Shodan - Supported by Binary Edge & WhoisXMLAPI

## What's New in the Plus Edition

This is a modernized fork of the original [Kamerka-GUI](https://github.com/woj-ciech/Kamerka-GUI) with the following major changes:

- **Leaflet.js + OpenStreetMap** replaces Google Maps — no API key required, no cost, fully open-source (BSD-2-Clause)
- **Nuclei vulnerability scanning** with 12 custom templates targeting China-IoT devices (Hikvision, Dahua, Huawei, ZTE)
- **Wappalyzer integration** for web technology fingerprinting of discovered devices
- **RTSP stream scanning** for camera devices
- **CSV and KML export** for search results
- **Celery progress tracking** with real-time task status in the UI
- **Comprehensive test suite** covering models, views, URL patterns, exports, and scanning tasks
- **Removed** Twitter and Flickr integrations (deprecated)
- **Removed** Google Maps API dependency

## NSA and CISA Recommend Immediate Actions to Reduce Exposure Across Operational Technologies and Control Systems

> Shodan, Kamerka, are creating a “perfect storm” of 
> 
> 1) easy access to unsecured assets, 
> 
> 2) use of common, open-source information about devices, and 
> 
> 3) an extensive list of exploits deployable via common exploit frameworks (e.g., Metasploit, Core Impact, and Immunity Canvas).

https://us-cert.cisa.gov/ncas/alerts/aa20-205a

## Usage

#### 1. Scan for Internet facing Industrial Control Systems, Medical and Internet of Things devices based on country or coordinates.
#### 2. Gather passive intelligence from WHOISXML, BinaryEdge and Shodan or active by scanning target directly.
#### 3. Thanks to indicators from devices and Leaflet maps, pinpoint device to specific place or facility (hospital, wastewater treatment plant, gas station, university, etc.)
#### 4. (Optional, not recommended) Guess/Bruteforce or use default password to gain access to the device. Some exploits are implemented for couple specific IoTs.
#### 5. Report devices in critical infrastructure to your local CERT.

## Features
- More than 100 ICS device queries
- Interactive maps powered by Leaflet.js and OpenStreetMap (no API key needed)
- Nuclei vulnerability scanning with custom China-IoT templates
- Wappalyzer web technology detection
- RTSP camera stream scanning
- CSV and KML export for search results
- Gallery section shows every gathered screenshot in one place
- Celery task progress tracking in the UI
- Possibility to implement own exploits or scanning techniques
- Support for NMAP scan in XML format as an input
- Find the route and change location of device
- Statistics for each search
- Position for vessels is scraped from device directly, rather than IP based
- Some devices return hints or location in the response. It's parsed and displayed as an indicator that helps to geolocate device.

## Articles
https://www.offensiveosint.io/hack-the-planet-with-amerka-gui-ultimate-internet-of-things-industrial-control-systems-reconnaissance-tool/

https://www.offensiveosint.io/offensive-osint-s01e03-intelligence-gathering-on-critical-infrastructure-in-southeast-asia/

https://www.offensiveosint.io/hack-like-its-2077-presenting-amerka-mobile/

https://www.zdnet.com/article/kamerka-osint-tool-shows-your-countrys-internet-connected-critical-infrastructure/

https://www.icscybersecurityconference.com/intelligence-gathering-on-u-s-critical-infrastructure/

## Installation

### Requirements
- Python 3
- Django (3.2 – 4.x)
- Celery (5.2+)
- Redis (4.0+)
- Shodan paid account
- BinaryEdge (Optional)
- WHOISXMLAPI (Optional)
- Pastebin PRO (Optional)
- [Wappalyzer CLI](https://github.com/AliasIO/wappalyzer) (Optional, for tech detection)
- [Nuclei](https://github.com/projectdiscovery/nuclei) (Optional, for vulnerability scanning)

> **Note:** Google Maps API is no longer required. Maps are rendered with Leaflet.js and OpenStreetMap tiles.

**Make sure your API keys are correct and put them in `keys.json` in the main directory.**

### Run
```bash
git clone https://github.com/webmaster-exit-1/Kamerka_Plus_GUI.git
cd Kamerka_Plus_GUI
pip3 install -r requirements.txt
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver
```

In a new window (in the main directory) run the Celery worker:
```bash
celery --app kamerka worker --loglevel=info
```

In a new window start Redis:
```bash
apt-get install redis
redis-server
```

The server should be available at `http://localhost:8000/`

### Running Tests
```bash
python3 manage.py test app_kamerka -v2
```


## Search
### Search for Industrial Control Devices in specific country
 ![](screens/search1.png)

- "All results" checkbox means get all results from Shodan, if it's turned off - only first page (100) results will be downloaded.
- "Own database" checkbox does not work but shows that is possible to integrate your own geolocation database.

### Search for Internet of things in specific coordinates
Type your coordinates in format "lat,lon", hardcoded radius is 20km.
  ![](screens/search2.png)

## Dashboard
   ![](screens/dashboard.png)

## Gallery
![](screens/gallery.png)

## Maps
### City map (Leaflet.js + OpenStreetMap)
 ![](screens/map.png)

### Industrial Control Systems in Poland - ~2.5k different devices
![](screens/map2.png)

## Statistics
![](screens/stats.png)

## Device map
![](screens/device_map.png)

## Intel
![](screens/intel.png)

## Geolocate
![](screens/map3.png)

## Scan & Exploit & Information
![](screens/exploit.png)

## Full list of supported devices with corresponding queries
https://github.com/webmaster-exit-1/Kamerka_Plus_GUI/blob/master/queries.md

## NMAP Scripts
- atg-info
- codesys
- cspv4-info
- dnp3-info
- enip-info
- fox-info
- modbus-discover
- modicon-info
- omron-info
- pcworx-info
- proconos-info
- s7-enumerate
- s7-info

## Nuclei Templates

Custom vulnerability templates for China-IoT devices, organized by vendor:

### Hikvision
- `hikvision-web-panel-detect` — Panel detection
- `hikvision-cve-2021-36260` — Command injection
- `hikvision-cve-2023-6895` — Known vulnerability

### Dahua
- `dahua-web-panel-detect` — Panel detection
- `dahua-dss-sqli` — SQL injection
- `dahua-cnvd-2017-06001` — Known vulnerability

### Huawei
- `huawei-hg5xx-vuln` — HG5xx series vulnerability
- `huawei-hg255s-lfi` — Local file inclusion
- `huawei-waf-detect` — WAF detection

### ZTE
- `zte-v8-detect` — V8 detection
- `zte-router-disclosure` — Information disclosure
- `zte-f460-rce` — Remote code execution

## Exploits
- CirCarLife SCADA 4.3.0 - Credential Disclosure
- VideoIQ - Remote file disclosure
- Grandstream UCM6202 1.0.18.13 - Remote Command Injection
- Contec Smart Home 4.15 - Unauthorized Password Reset
- Netwave IP Camera - Password Disclosure
- Amcrest Cameras 2.520.AC00.18.R - Unauthenticated Audio Streaming
- Lutron Quantum 2.0 - 3.2.243 - Information Disclosure
- Bosch Security Systems DVR 630/650/670 Series - Multiple Vulnerabilities


## Used components
- Leaflet.js (v1.9.4) - https://leafletjs.com/ (BSD-2-Clause)
- OpenStreetMap tiles - https://www.openstreetmap.org/
- Joli admin template - https://github.com/sbilly/joli-admin
- Search form - Colorlib Search Form v15
- country picker - https://github.com/mojoaxel/bootstrap-select-country
- Multiselect - https://github.com/varundewan/multiselect/
- Arsen Zbidniakov Flat UI Checkbox https://codepen.io/ARS/pen/aeDHE/
- icon from icons8.com and icon-icons.com
- Nmap Scripts from NMAP Script Engine and Digital Bond repository
- Exploits from exploit-db and routersploit

## License

MIT License — see [LICENSE.md](LICENSE.md) for details.

## Additional
- I'm not responsible for any damage caused by using this tool.
