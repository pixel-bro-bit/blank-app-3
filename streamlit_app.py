import streamlit as st
import psutil
import os
import hashlib
import magic
import requests
import json
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

# Initialize VirusTotal API (users need to add their API key in Secrets)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

def get_file_type(file_path):
    """Detect file type using magic library"""
    try:
        return magic.from_file(file_path, mime=True)
    except:
        return "unknown"

def check_virustotal(file_hash):
    """Check file hash against VirusTotal database"""
    if not VIRUSTOTAL_API_KEY:
        return None

    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        "apikey": VIRUSTOTAL_API_KEY,
        "resource": file_hash
    }
    try:
        response = requests.get(url, params=params)
        return response.json() if response.status_code == 200 else None
    except:
        return None

def heuristic_analysis(file_path):
    """Perform basic heuristic analysis"""
    suspicious_patterns = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            # Check for suspicious patterns
            if b'CreateRemoteThread' in content:
                suspicious_patterns.append("Process injection capability detected")
            if b'WriteProcessMemory' in content:
                suspicious_patterns.append("Memory manipulation capability detected")
            if b'RegCreateKey' in content:
                suspicious_patterns.append("Registry modification capability detected")
    except:
        pass
    return suspicious_patterns

def save_transaction(amount, features):
    """Save transaction details"""
    transaction_file = os.path.join(os.path.expanduser("~"), ".transactions.json")
    transactions = []
    if os.path.exists(transaction_file):
        try:
            with open(transaction_file, 'r') as f:
                transactions = json.load(f)
        except:
            pass

    transactions.append({
        'timestamp': datetime.now().isoformat(),
        'amount': amount,
        'features': features
    })

    with open(transaction_file, 'w') as f:
        json.dump(transactions, f)

def save_scan_history(scan_result):
    """Save scan results to history"""
    history_file = os.path.join(os.path.expanduser("~"), ".scan_history.json")
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
        except:
            pass

    history.append({
        'timestamp': datetime.now().isoformat(),
        'result': scan_result
    })

    with open(history_file, 'w') as f:
        json.dump(history[-100:], f)  # Keep last 100 scans

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def scan_processes():
    """Scan and automatically eliminate suspicious processes"""
    suspicious_processes = []
    suspicious_keywords = ['malware', 'trojan', 'backdoor', 'virus', 'keylog', 'spyware', 'adware', 'ransomware']
    high_cpu_threshold = 90.0  # CPU usage percentage threshold
    high_memory_threshold = 90.0  # Memory usage percentage threshold

    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            # Check for suspicious process names
            is_suspicious = any(keyword in proc.info['name'].lower() for keyword in suspicious_keywords)

            # Check for high resource usage
            if proc.info['cpu_percent'] > high_cpu_threshold or proc.info['memory_percent'] > high_memory_threshold:
                is_suspicious = True

            # Check for suspicious command line arguments
            if proc.info['cmdline']:
                is_suspicious = is_suspicious or any(keyword in ' '.join(proc.info['cmdline']).lower() for keyword in suspicious_keywords)

            if is_suspicious:
                # Kill the process forcefully
                try:
                    process = psutil.Process(proc.info['pid'])
                    process.kill()  # More aggressive than terminate()
                    proc.info['eliminated'] = True
                    proc.info['elimination_method'] = 'Killed suspicious process'
                except:
                    proc.info['eliminated'] = False
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_processes

def eliminate_threat(file_path):
    """Safely eliminate detected threat"""
    try:
        quarantine_dir = os.path.join(os.path.expanduser("~"), ".quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = os.path.join(quarantine_dir, f"threat_{timestamp}_{os.path.basename(file_path)}")
        os.rename(file_path, quarantine_path)
        return True, "Threat quarantined successfully"
    except Exception as e:
        try:
            os.remove(file_path)
            return True, "Threat eliminated successfully"
        except Exception as e:
            return False, f"Failed to eliminate threat: {str(e)}"

def scan_directory(path):
    """Scan directory for suspicious files"""
    suspicious_files = []
    extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.js', '.hta']

    for root, _, files in os.walk(path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                file_hash = get_file_hash(file_path)
                if file_hash:
                    file_type = get_file_type(file_path)
                    vt_result = check_virustotal(file_hash)
                    heuristic_results = heuristic_analysis(file_path)

                    suspicious_files.append({
                        'path': file_path,
                        'hash': file_hash,
                        'size': os.path.getsize(file_path),
                        'type': file_type,
                        'vt_result': vt_result,
                        'heuristic_flags': heuristic_results,
                        'eliminated': False,
                        'elimination_msg': ''
                    })
    return suspicious_files

def schedule_scan():
    """Schedule a scan for the specified directory"""
    scheduler = BackgroundScheduler()
    scan_path = st.session_state.get('scheduled_scan_path', os.path.expanduser("~"))
    scheduler.add_job(scan_directory, 'interval', hours=24, args=[scan_path])
    scheduler.start()

def scan_device():
    """Scan device information, system resources, and eliminate threats"""
    device_info = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'running_processes': len(list(psutil.process_iter())),
        'network_connections': len(psutil.net_connections()),
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        'threats_found': 0,
        'threats_eliminated': 0
    }
    
    # Scan for suspicious processes
    suspicious_procs = scan_processes()
    if suspicious_procs:
        device_info['threats_found'] += len(suspicious_procs)
        device_info['threats_eliminated'] += len(suspicious_procs)
    
    # Scan home directory for suspicious files
    suspicious_files = scan_directory(os.path.expanduser("~"))
    if suspicious_files:
        device_info['threats_found'] += len(suspicious_files)
        for file in suspicious_files:
            # Safely check for threats with proper None handling
            heuristic_flags = file.get('heuristic_flags', [])
            vt_result = file.get('vt_result', {})
            has_virus = False
            
            if heuristic_flags and any(heuristic_flags):
                has_virus = True
            if vt_result and vt_result.get('positives', 0) > 0:
                has_virus = True
                
            if has_virus:
                success, _ = eliminate_threat(file['path'])
                if success:
                    device_info['threats_eliminated'] += 1
    
    return device_info

def main():
    st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #FF6B6B, #4ECDC4);
        padding: 20px;
        border-radius: 10px;
    }
    .nav-bar {
        display: flex;
        justify-content: space-around;
        padding: 1rem;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .nav-item {
        color: white;
        text-decoration: none;
        padding: 8px 16px;
        border-radius: 5px;
        transition: background-color 0.3s;
    }
    .nav-item:hover {
        background-color: rgba(255, 255, 255, 0.2);
    }
    .scan-type {
        background: rgba(78, 205, 196, 0.1);
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .stButton button {
        background-color: #FF6B6B !important;
        color: white !important;
        border: none !important;
        border-radius: 5px !important;
        transition: all 0.3s ease !important;
    }
    .stButton button:hover {
        background-color: #4ECDC4 !important;
        transform: translateY(-2px);
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("<div class='main'><h1 style='color: white; text-align: center;'>🛡️ Enhanced Antivirus Scanner</h1></div>", unsafe_allow_html=True)

    # Navigation Bar
    selected_page = st.selectbox("", ["Home", "Scans", "About Us", "Contact Us"], key="nav")

    if selected_page == "Home":
        st.header("Welcome to Enhanced Antivirus Scanner")
        st.markdown("""
        <div class='scan-type'>
            <h3>Available Scan Types:</h3>
            <ul>
                <li>🔍 Quick Scan - Rapid check of common malware locations</li>
                <li>🌐 Process Scanner - Monitor and eliminate suspicious processes</li>
                <li>📁 Directory Scanner - Deep scan of specific directories</li>
                <li>⚡ Real-time Protection - Continuous system monitoring</li>
                <li>📊 Heuristic Analysis - Advanced threat detection</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

        if selected_page == "Home":
            # Code for Home page
            print("Welcome to the Home page")
        elif selected_page == "Scans":
            # Code for Scans page
            print("Welcome to the Scans page")
        elif selected_page == "About Us":
            # Code for About Us page
            print("Welcome to the About Us page")
        # Admin authentication 
        if 'is_admin' not in st.session_state:
            st.session_state.is_admin = False

    # Admin login section in sidebar
    st.sidebar.markdown("---")
    st.sidebar.header("Admin Login")
    admin_code = st.sidebar.text_input("Enter admin code:", type="password")
    if admin_code == "k_best":
        st.session_state.is_admin = True
        st.sidebar.success("Admin access granted!")

    # Authentication handling
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'payment_made' not in st.session_state:
        st.session_state.payment_made = False

    if not st.session_state.authenticated and not st.session_state.is_admin:
        st.header("Login/Sign Up")
        tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Admin Login"])

        with tab1:
            login_username = st.text_input("Username", key="login_user")
            login_password = st.text_input("Password", type="password", key="login_pass")
            if st.button("Login"):
                if login_username and login_password:
                    # Simple demo authentication
                    if login_username == "demo" and login_password == "demo123":
                        st.session_state.authenticated = True
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
                else:
                    st.warning("Please fill in all fields")

        with tab2:
            new_username = st.text_input("Choose Username", key="signup_user")
            new_password = st.text_input("Choose Password", type="password", key="signup_pass")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_pass")
            if st.button("Sign Up"):
                if new_username and new_password and confirm_password:
                    if new_password == confirm_password:
                        # In a real app, save user credentials securely
                        st.session_state.authenticated = True
                        st.success("Account created successfully!")
                        st.experimental_rerun()
                    else:
                        st.error("Passwords don't match")
                else:
                    st.warning("Please fill in all fields")

        with tab3:
            admin_login_code = st.text_input("Admin Code", type="password", key="admin_login")
            if st.button("Login as Admin"):
                if admin_login_code == "K_best":
                    st.session_state.is_admin = True
                    st.success("Admin access granted!")
                    st.rerun()
                else:
                    st.error("Invalid admin code")

    elif not st.session_state.is_admin and not st.session_state.payment_made:
        st.warning("⚠️ Premium features require payment")
        st.info("💳 Premium Features ($9.99):")
        st.markdown("- Automatic virus elimination")
        st.markdown("- Advanced heuristic scanning")
        st.markdown("- Real-time protection")

        st.write("Payment Details ($9.99)")
        card_number = st.text_input("Credit Card Number", type="password")
        expiry = st.text_input("Expiry Date (MM/YY)")
        cvv = st.text_input("CVV", type="password", max_chars=3)

        if st.button("Submit Payment"):
            # This is a simple simulation - in production, use a real payment processor
            if len(card_number) == 16 and len(cvv) == 3 and expiry:
                # Simulate balance check (in real implementation, this would connect to payment processor)
                has_sufficient_balance = len(card_number) % 2 == 0  # Simple simulation

                if has_sufficient_balance:
                    st.session_state.payment_made = True
                    save_transaction(9.99, ["Automatic virus elimination", "Advanced heuristic scanning", "Real-time protection"])
                    st.success("Payment successful! All features unlocked.")
                    st.experimental_rerun()
                else:
                    st.error("Insufficient balance. Please try another card.")
            else:
                st.error("Invalid card details. Please check and try again.")

    # Admin special features
    if st.session_state.is_admin:
        st.sidebar.markdown("---")
        st.sidebar.markdown("<div style='background-color: #FF6B6B; padding: 10px; border-radius: 5px; color: white;'><h2>Admin Features</h2></div>", unsafe_allow_html=True)
        st.sidebar.markdown("- 🔍 Deep scan enabled")
        st.sidebar.markdown("- 🚀 Priority processing")
        st.sidebar.markdown("- 📊 Advanced analytics")

        # Add admin-only scan option
        deep_scan = st.sidebar.checkbox("Enable deep scan")

        # Transaction History Section
        st.sidebar.markdown("---")
        st.sidebar.markdown("<div style='background-color: #4ECDC4; padding: 10px; border-radius: 5px; color: white;'><h2>Transaction History</h2></div>", unsafe_allow_html=True)

        transaction_file = os.path.join(os.path.expanduser("~"), ".transactions.json")
        if os.path.exists(transaction_file):
            with open(transaction_file, 'r') as f:
                transactions = json.load(f)
                total_revenue = sum(t['amount'] for t in transactions)
                st.sidebar.markdown(f"**Total Revenue**: ${total_revenue:.2f}")
                st.sidebar.markdown("**Recent Transactions:**")
                for transaction in transactions[-5:]:  # Show last 5 transactions
                    st.sidebar.markdown(f"- ${transaction['amount']} ({datetime.fromisoformat(transaction['timestamp']).strftime('%Y-%m-%d %H:%M')})")
        else:
            st.sidebar.markdown("No transactions yet")

    st.sidebar.header("Scan Options")
    scan_type = st.sidebar.radio(
        "Select scan type:",
        ["Device Scanner", "Process Scanner", "Directory Scanner", "Scan History"]
    )

    if scan_type == "Device Scanner":
        if st.button("Scan Device"):
            with st.spinner("Scanning device..."):
                device_info = scan_device()
                st.write("📊 Device Scan Results:")
                st.progress(device_info['cpu_percent'] / 100, "CPU Usage")
                st.progress(device_info['memory_percent'] / 100, "Memory Usage")
                st.progress(device_info['disk_usage'] / 100, "Disk Usage")
                st.write(f"Running Processes: {device_info['running_processes']}")
                st.write(f"Network Connections: {device_info['network_connections']}")
                st.write(f"System Boot Time: {device_info['boot_time']}")
                
                if device_info['threats_found'] > 0:
                    st.error(f"⚠️ Found {device_info['threats_found']} threats!")
                    st.success(f"✅ Eliminated {device_info['threats_eliminated']} threats")
                else:
                    st.success("✅ No threats detected")
                
                if device_info['cpu_percent'] > 80 or device_info['memory_percent'] > 80:
                    st.warning("⚠️ High system resource usage detected!")
                else:
                    st.info("✅ System resources are at normal levels")

    elif scan_type == "Process Scanner":
        if st.button("Scan Running Processes"):
            with st.spinner("Scanning processes..."):
                suspicious_procs = scan_processes()
                save_scan_history({'type': 'process', 'findings': suspicious_procs})

                if suspicious_procs:
                    st.error(f"Found {len(suspicious_procs)} suspicious processes!")
                    for proc in suspicious_procs:
                        st.write(f"⚠️ Process: {proc['name']} (PID: {proc['pid']})")
                        st.write(f"Created: {datetime.fromtimestamp(proc['create_time'])}")
                else:
                    st.success("No suspicious processes found!")

    elif scan_type == "Directory Scanner":
        scan_path = st.text_input("Enter directory path to scan:", value=os.path.expanduser("~"))

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Scan Directory"):
                if os.path.exists(scan_path):
                    with st.spinner("Scanning directory..."):
                        if st.session_state.is_admin and 'deep_scan' in locals() and deep_scan:
                            st.info("Performing deep scan with admin privileges...")
                            # Enhanced scanning for admins
                            suspicious_files = scan_directory(scan_path)
                            # Add additional admin-only scans here
                        elif st.session_state.payment_made or st.session_state.is_admin:
                            suspicious_files = scan_directory(scan_path)
                        else:
                            st.error("Please make payment or login as admin to perform scans")
                            suspicious_files = []
                        save_scan_history({'type': 'directory', 'path': scan_path, 'findings': suspicious_files})

                        if suspicious_files:
                            st.error(f"Found {len(suspicious_files)} potentially suspicious files!")
                            for file in suspicious_files:
                                # Automatically determine if file is dangerous
                                is_dangerous = False
                                danger_score = 0

                                # Check VirusTotal results
                                if file['vt_result']:
                                    positives = file['vt_result'].get('positives', 0)
                                    total = file['vt_result'].get('total', 0)
                                    if total > 0:
                                        detection_rate = positives / total
                                        if detection_rate > 0.1:  # More than 10% detection rate
                                            danger_score += 2
                                            is_dangerous = True

                                # Check heuristic flags
                                if file['heuristic_flags']:
                                    danger_score += len(file['heuristic_flags'])
                                    is_dangerous = True

                                # Check file type
                                dangerous_extensions = ['.exe', '.dll', '.scr', '.bat', '.vbs', '.js']
                                if any(file['path'].lower().endswith(ext) for ext in dangerous_extensions):
                                    danger_score += 1

                                # Automatically eliminate if dangerous
                                if is_dangerous or danger_score >= 2:
                                    success, msg = eliminate_threat(file['path'])
                                    file['eliminated'] = success
                                    file['elimination_msg'] = msg
                                    st.warning(f"⚠️ Automatic elimination: {msg} (Danger Score: {danger_score})")


                                st.write(f"⚠️ File: {file['path']}")
                                st.write(f"Type: {file['type']}")
                                st.write(f"SHA-256: {file['hash']}")
                                st.write(f"Size: {file['size']} bytes")

                                if file['vt_result']:
                                    positives = file['vt_result'].get('positives', 0)
                                    total = file['vt_result'].get('total', 0)
                                    st.write(f"VirusTotal: {positives}/{total} detections")

                                if file['heuristic_flags']:
                                    st.write("Heuristic Analysis Flags:")
                                    for flag in file['heuristic_flags']:
                                        st.write(f"- {flag}")

                                if not file.get('eliminated', False):
                                    if st.session_state.payment_made or st.session_state.is_admin:
                                        confirm_key = f"confirm_{file['path']}"
                                    if 'confirm_state' not in st.session_state:
                                        st.session_state.confirm_state = {}

                                    if st.button("Eliminate Threat", key=file['path']):
                                        st.session_state.confirm_state[confirm_key] = True

                                    if st.session_state.confirm_state.get(confirm_key, False):
                                        st.warning("Are you sure you want to eliminate this threat?")
                                        col3, col4 = st.columns(2)
                                        with col3:
                                            if st.button("Yes", key=f"yes_{file['path']}"):
                                                success, msg = eliminate_threat(file['path'])
                                                file['eliminated'] = success
                                                file['elimination_msg'] = msg
                                                if success:
                                                    st.success(msg)
                                                else:
                                                    st.error(msg)
                                                st.session_state.confirm_state[confirm_key] = False
                                        with col4:
                                            if st.button("No", key=f"no_{file['path']}"):
                                                st.session_state.confirm_state[confirm_key] = False
                                else:
                                    st.info(file['elimination_msg'])
                                st.write("---")
                        else:
                            st.markdown("<div style='background-color: #4ECDC4; padding: 20px; border-radius: 10px; color: white;'>✨ No suspicious files found!</div>", unsafe_allow_html=True)
                else:
                    st.error("Invalid directory path!")

        with col2:
            if st.button("Schedule Daily Scan"):
                st.session_state.scheduled_scan_path = scan_path
                schedule_scan()
                st.success("Daily scan scheduled!")

    else:  # Scan History
        history_file = os.path.join(os.path.expanduser("~"), ".scan_history.json")
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                history = json.load(f)
                for entry in history:
                    st.write(f"Scan Time: {entry['timestamp']}")
                    st.write(f"Type: {entry['result']['type']}")
                    if entry['result']['type'] == 'directory':
                        st.write(f"Path: {entry['result']['path']}")
                    st.write(f"Findings: {len(entry['result']['findings'])} suspicious items")
                    st.write("---")
        else:
            st.info("No scan history available")

    st.sidebar.markdown("---")
    st.sidebar.info("""
    ℹ️ Enhanced Antivirus Scanner features:
    - Process and file scanning
    - VirusTotal integration
    - File type detection
    - Heuristic analysis
    - Scheduled scanning
    - Scan history tracking
    """)

    if selected_page == "Home":
        # Home page code
        print("Welcome to the Home page")
    elif selected_page == "About Us":
        # About Us page code
        print("About Us page")
    elif selected_page == "Contact Us":
        # Contact Us page code
        st.header("ℹ️ About Us")
        st.markdown("""
        <div style='background-color: #4ECDC4; padding: 20px; border-radius: 10px; color: white;'>
            <h3>Welcome to Enhanced Antivirus Scanner</h3>
            <p>We are dedicated to providing cutting-edge protection for your system with:</p>
            <ul>
                <li>Advanced threat detection</li>
                <li>Real-time monitoring</li>
                <li>Automatic threat elimination</li>
                <li>Regular security updates</li>
            </ul>
            <p>This is an anti virus software. Enjoy!</p>
        </div>
        """, unsafe_allow_html=True)

    elif selected_page == "Contact Us":
        st.header("📧 Contact Us")
        contact_name = st.text_input("Your Name")
        contact_email = st.text_input("Your Email")
        contact_message = st.text_area("Message")

        if st.button("Send Message"):
            if contact_name and contact_email and contact_message:
                try:
                    import smtplib
                    from email.mime.text import MIMEText

                    msg = MIMEText(f"From: {contact_name}\nEmail: {contact_email}\n\nMessage:\n{contact_message}")
                    msg['Subject'] = f'Contact Form Message from {contact_name}'
                    msg['From'] = contact_email
                    msg['To'] = os.getenv("EMAIL", "default@example.com")

                    # Using Gmail SMTP
                    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                        email = os.getenv("EMAIL")
                        email_password = os.getenv("EMAIL_PASSWORD")
                        if email and email_password:
                            server.login(email, email_password)
                            server.send_message(msg)
                            st.success("Message sent successfully!")
                        else:
                            st.error("Email configuration is not set up. Please contact administrator.")
                except Exception as e:
                    st.error(f"Failed to send message. Please try again later.")
            else:
                st.warning("Please fill in all fields")

if __name__ == "__main__":
    main()
