import streamlit as st
import time
import pandas as pd
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import hashlib
import os
import secrets

# Import modules
try:
    from did import create_peer_did, update_did
    from zkp import generate_keypair, create_zk_proof, verify_zk_proof, ZKPError
    from encryption import generate_rsa_keypair, encrypt_data, decrypt_data
    from mongodb_manager import MongoDBManager, DatabaseError, get_db_manager, test_connection, PYMONGO_AVAILABLE
except ImportError as e:
    st.error(f"Import error: {e}")
    st.error("Please ensure all required modules are available")
    st.stop()

# Try to import plotly
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB Atlas Configuration
MONGODB_ATLAS_CONNECTION = "mongodb+srv://pirate-2727:1iVuVXeeRN8CTEem@cluster0.dp9isnx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DATABASE_NAME = "did_identity_system"

# Page configuration
st.set_page_config(
    page_title="DID System - Atlas",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
    .atlas-badge {
        background-color: #00684A;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .cloud-badge {
        background-color: #4285f4;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.8rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Helper function for Streamlit rerun compatibility
def rerun_app():
    """Handle Streamlit rerun with version compatibility"""
    try:
        st.rerun()
    except AttributeError:
        try:
            st.experimental_rerun()
        except AttributeError:
            st.warning("Please refresh the page manually")

class SecurityManager:
    """Enhanced security features with MongoDB support"""
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION = timedelta(minutes=15)
    SESSION_TIMEOUT = timedelta(hours=2)

    @staticmethod
    def is_locked_out(did: str, db_manager: MongoDBManager = None) -> bool:
        if 'lockouts' not in st.session_state:
            st.session_state.lockouts = {}

        if did in st.session_state.lockouts:
            lockout_time = st.session_state.lockouts[did]
            if datetime.now() - lockout_time < SecurityManager.LOCKOUT_DURATION:
                return True
            else:
                del st.session_state.lockouts[did]
        return False

    @staticmethod
    def record_failed_attempt(did: str, db_manager: MongoDBManager = None):
        if 'failed_attempts' not in st.session_state:
            st.session_state.failed_attempts = {}

        attempts = st.session_state.failed_attempts.get(did, 0) + 1
        st.session_state.failed_attempts[did] = attempts

        if attempts >= SecurityManager.MAX_LOGIN_ATTEMPTS:
            if 'lockouts' not in st.session_state:
                st.session_state.lockouts = {}
            st.session_state.lockouts[did] = datetime.now()
            st.session_state.failed_attempts[did] = 0

        # Log failed attempt to database if available
        if db_manager and db_manager.is_connected():
            log_entry = {
                'timestamp': datetime.now(),
                'did': did,
                'action': 'failed_login_attempt',
                'details': f'Failed attempt #{attempts}',
                'status': 'failure'
            }
            db_manager.store_log(log_entry)

    @staticmethod
    def clear_failed_attempts(did: str):
        if 'failed_attempts' in st.session_state and did in st.session_state.failed_attempts:
            del st.session_state.failed_attempts[did]

    @staticmethod
    def is_session_expired() -> bool:
        if 'session_start' not in st.session_state:
            return True
        session_start = st.session_state.session_start
        return datetime.now() - session_start > SecurityManager.SESSION_TIMEOUT

def safe_encrypt_data(public_key_pem: str, data: str) -> tuple[str, bool]:
    """Safely encrypt data with size checking"""
    try:
        if len(data.encode('utf-8')) <= 190:
            encrypted = encrypt_data(public_key_pem, data)
            return encrypted, True
        else:
            logger.warning(f"Data too large for RSA encryption ({len(data)} bytes)")
            return data, False
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return data, False

def safe_decrypt_data(private_key_pem: str, data: str, was_encrypted: bool) -> str:
    """Safely decrypt data if it was encrypted"""
    if not was_encrypted:
        return data
    try:
        return decrypt_data(private_key_pem, data)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return data

def validate_did_format(did: str) -> bool:
    """Basic DID format validation"""
    return bool(did and did.startswith("did:peer:") and len(did) > 15)

def initialize_session_state():
    """Initialize session state with Atlas connection"""
    defaults = {
        'session': None,
        'session_start': None,
        'failed_attempts': {},
        'lockouts': {},
        'settings': {
            'auto_logout': True,
            'detailed_logs': True,
            'encryption_enabled': False,
            'mongodb_enabled': True,
            'mongodb_connection': MONGODB_ATLAS_CONNECTION,
            'database_name': DATABASE_NAME
        },
        'db_manager': None,
        'db_connected': False
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Initialize database connection
    initialize_database()

    # Generate server RSA keys if not exists
    if 'server_priv_key' not in st.session_state:
        try:
            pub, priv = generate_rsa_keypair()
            st.session_state.server_pub_key = pub
            st.session_state.server_priv_key = priv
        except Exception as e:
            st.error(f"Failed to generate server keys: {e}")

def initialize_database():
    """Initialize MongoDB Atlas connection"""
    if not PYMONGO_AVAILABLE:
        st.session_state.db_connected = False
        st.session_state.db_manager = None
        return

    if st.session_state.settings['mongodb_enabled']:
        try:
            connection_string = st.session_state.settings['mongodb_connection']

            # Create database manager with custom database name
            class AtlasMongoDBManager(MongoDBManager):
                def __init__(self, connection_string: str, db_name: str):
                    self.connection_string = connection_string
                    self.db_name = db_name
                    self.client = None
                    self.db = None
                    self.connected = False

                    if not PYMONGO_AVAILABLE:
                        raise DatabaseError("PyMongo library not installed")

                    self.connect()

            # Test connection first
            if test_connection(connection_string):
                st.session_state.db_manager = AtlasMongoDBManager(
                    connection_string, 
                    st.session_state.settings['database_name']
                )
                st.session_state.db_connected = True
                logger.info("MongoDB Atlas connection established")
            else:
                st.session_state.db_connected = False
                st.session_state.db_manager = None
                logger.warning("MongoDB Atlas connection test failed")
        except Exception as e:
            st.session_state.db_connected = False
            st.session_state.db_manager = None
            logger.error(f"MongoDB Atlas initialization failed: {e}")
    else:
        st.session_state.db_connected = False
        st.session_state.db_manager = None

def log_activity(did: str, action: str, details: str, status: str = "success"):
    """Log activity to MongoDB Atlas and session state"""
    log_entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'did': did,
        'action': action,
        'details': details,
        'status': status
    }

    # Store in MongoDB Atlas if available
    if st.session_state.db_connected and st.session_state.db_manager:
        try:
            st.session_state.db_manager.store_log(log_entry)
        except Exception as e:
            logger.error(f"Failed to store log in MongoDB Atlas: {e}")

    # Also store in session state for immediate access
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    st.session_state.logs.append(log_entry)

def render_header():
    """Render header with Atlas status"""
    st.markdown('<h1 class="main-header">🔐 DID System with MongoDB Atlas</h1>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("**Cloud Database Storage with MongoDB Atlas**")
    with col2:
        if st.session_state.db_connected:
            st.markdown('<span class="atlas-badge">ATLAS</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="cloud-badge">OFFLINE</span>', unsafe_allow_html=True)
    with col3:
        if not PYMONGO_AVAILABLE:
            st.error("Install PyMongo")

    st.markdown("---")

    # Metrics from Atlas database
    col1, col2, col3, col4 = st.columns(4)

    # Get stats from Atlas database if available
    if st.session_state.db_connected and st.session_state.db_manager:
        try:
            stats = st.session_state.db_manager.get_user_stats()
            total_users = stats.get('total_users', 0)
            recent_users = stats.get('recent_registrations', 0)
        except Exception:
            total_users = 0
            recent_users = 0
    else:
        total_users = 0
        recent_users = 0

    with col1:
        st.metric("Total Users", total_users)
    with col2:
        st.metric("Active Sessions", 1 if st.session_state.session else 0)
    with col3:
        st.metric("Recent Registrations", recent_users)
    with col4:
        db_status = "Atlas Connected" if st.session_state.db_connected else "Offline"
        st.metric("Database", db_status)

def render_sidebar():
    """Render sidebar with Atlas configuration"""
    with st.sidebar:
        st.header("System Status")

        if st.session_state.session:
            st.success("✅ Logged in")
            st.text(f"DID: {st.session_state.session[:25]}...")

            if st.button("🚪 Logout"):
                old_session = st.session_state.session
                st.session_state.session = None
                st.session_state.session_start = None
                log_activity(old_session, "logout", "User logged out from Atlas system")
                st.success("Logged out successfully!")
                time.sleep(1)
                rerun_app()
        else:
            st.info("🔒 Not logged in")

        st.markdown("---")

        # Database Status
        st.subheader("☁️ MongoDB Atlas")
        if st.session_state.db_connected:
            st.success("✅ Connected to Atlas")
            st.text("🌍 Cloud Database Active")
        else:
            st.error("❌ Atlas Connection Failed")

        if not PYMONGO_AVAILABLE:
            st.error("PyMongo required")
            st.code("pip install pymongo")

        # Database Configuration
        with st.expander("⚙️ Atlas Settings", expanded=False):
            st.info("**MongoDB Atlas Cluster:**")
            st.text("Cluster0 (dp9isnx)")
            st.text("Database: did_identity_system")

            st.session_state.settings['mongodb_enabled'] = st.checkbox(
                "Enable MongoDB Atlas", 
                value=st.session_state.settings.get('mongodb_enabled', True)
            )

            # Show current connection (masked for security)
            masked_connection = st.session_state.settings['mongodb_connection']
            if "pirate-2727:" in masked_connection:
                masked_connection = masked_connection.replace(
                    "pirate-2727:1iVuVXeeRN8CTEem", 
                    "pirate-2727:***HIDDEN***"
                )
            st.text(f"Connection: {masked_connection[:50]}...")

            if st.button("🔄 Reconnect to Atlas"):
                initialize_database()
                rerun_app()

        st.markdown("---")

        # Settings
        st.subheader("⚙️ Settings")
        st.session_state.settings['encryption_enabled'] = st.checkbox(
            "Enable encryption", 
            value=st.session_state.settings.get('encryption_enabled', False),
            help="Encrypt sensitive data before storing in Atlas"
        )

def render_registration():
    """Registration tab with Atlas storage"""
    st.header("👤 User Registration")

    if not st.session_state.db_connected:
        st.error("⚠️ MongoDB Atlas offline - registration may fail")
    else:
        st.success("☁️ Ready to store users in MongoDB Atlas cloud database")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Generate Identity")

        if st.button("🎯 Generate DID and Store in Atlas", type="primary"):
            with st.spinner("Generating keys and storing in MongoDB Atlas..."):
                try:
                    # Generate keypairs
                    priv_key, pub_key = generate_keypair()
                    rsa_pub, rsa_priv = generate_rsa_keypair()
                    did = create_peer_did(pub_key)

                    # Handle encryption
                    if st.session_state.settings['encryption_enabled']:
                        stored_pub_key, pub_encrypted = safe_encrypt_data(st.session_state.server_pub_key, pub_key)
                        stored_rsa_pub, rsa_encrypted = safe_encrypt_data(st.session_state.server_pub_key, rsa_pub)
                    else:
                        stored_pub_key, pub_encrypted = pub_key, False
                        stored_rsa_pub, rsa_encrypted = rsa_pub, False

                    # Prepare user data
                    user_data = {
                        'pub_key': stored_pub_key,
                        'pub_rsa': stored_rsa_pub,
                        'created': datetime.now(),
                        'pub_key_encrypted': pub_encrypted,
                        'rsa_encrypted': rsa_encrypted
                    }

                    # Store in MongoDB Atlas
                    stored_in_atlas = False
                    if st.session_state.db_connected and st.session_state.db_manager:
                        try:
                            st.session_state.db_manager.store_user(did, user_data)
                            stored_in_atlas = True
                            st.success("✅ User stored in MongoDB Atlas cloud database!")
                        except DatabaseError as e:
                            if "already exists" in str(e):
                                st.error(f"❌ User with this DID already exists in Atlas database")
                                return
                            else:
                                st.error(f"❌ Atlas storage failed: {e}")
                                return
                        except Exception as e:
                            st.error(f"❌ Unexpected Atlas error: {e}")
                            return
                    else:
                        st.error("❌ Cannot store user - MongoDB Atlas not connected")
                        return

                    log_activity(did, "registration", f"New DID created and stored in Atlas (encrypted: {any([pub_encrypted, rsa_encrypted])})")

                    st.markdown('<div class="success-box">', unsafe_allow_html=True)
                    st.success("🎉 Identity Created and Stored Successfully!")
                    st.success("☁️ Permanently stored in MongoDB Atlas cloud database")
                    st.success("🌍 You can now login from anywhere, anytime!")
                    st.markdown('</div>', unsafe_allow_html=True)

                    st.info(f"**DID:** `{did}`")

                    # Show encryption status
                    if pub_encrypted:
                        st.success("🔐 ECDSA public key encrypted in Atlas")
                    else:
                        st.info("🔓 ECDSA public key stored unencrypted in Atlas")

                    if rsa_encrypted:
                        st.success("🔐 RSA public key encrypted in Atlas")
                    else:
                        st.info("🔓 RSA public key stored unencrypted in Atlas (too large)")

                    # Keys display
                    with st.expander("🔑 Private Keys (Save Securely!)"):
                        st.warning("⚠️ **IMPORTANT**: These private keys are NOT stored in the database. Save them now!")

                        st.text("ECDSA Private Key (for authentication):")
                        st.code(priv_key)
                        st.download_button("💾 Download ECDSA Key", priv_key, "ecdsa_key.txt", key="dl_ecdsa")

                        st.text("RSA Private Key (for encryption):")
                        st.text_area("", rsa_priv, height=200, key="rsa_display")
                        st.download_button("💾 Download RSA Key", rsa_priv, "rsa_key.pem", key="dl_rsa")

                    st.error("🚨 **CRITICAL**: Save your private keys now! They cannot be recovered if lost!")
                    st.success("✅ Your DID is now permanently stored in MongoDB Atlas - you can login anytime!")

                except Exception as e:
                    st.markdown('<div class="error-box">', unsafe_allow_html=True)
                    st.error(f"Registration failed: {e}")
                    st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.subheader("☁️ Atlas Benefits")
        st.markdown("""
        **MongoDB Atlas Cloud:**
        - ✅ Global accessibility
        - ✅ 99.9% uptime SLA
        - ✅ Automatic backups
        - ✅ Enterprise security
        - ✅ Scalable storage

        **Your Registration:**
        1. Generate DID and keys
        2. Store in Atlas cloud database
        3. Download private keys securely
        4. Login from anywhere, anytime

        **Database Status:**
        """)

        if st.session_state.db_connected:
            st.success("🟢 Connected to Atlas")
            st.text("Ready for registration")
        else:
            st.error("🔴 Atlas disconnected")
            st.text("Check internet connection")

def render_login():
    """Login tab with Atlas authentication"""
    st.header("🔐 Zero-Knowledge Authentication")
    st.info("🌍 Login with credentials stored in MongoDB Atlas cloud database")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Login Form")

        did_input = st.text_input("🆔 DID", placeholder="did:peer:2.Vz...")
        priv_key_input = st.text_input("🔑 ECDSA Private Key", type="password")

        # Validation
        inputs_valid = bool(did_input and priv_key_input)
        did_format_valid = validate_did_format(did_input) if did_input else False
        is_locked = SecurityManager.is_locked_out(did_input, st.session_state.db_manager) if did_input else False

        if did_input and not did_format_valid:
            st.error("❌ Invalid DID format")

        if is_locked:
            st.error("🚫 Account locked (15 minutes)")

        if st.button("🚀 Login with Atlas Authentication", disabled=not (inputs_valid and did_format_valid and not is_locked), type="primary"):
            with st.spinner("Authenticating with MongoDB Atlas..."):
                try:
                    user_info = None

                    # Get user from MongoDB Atlas
                    if st.session_state.db_connected and st.session_state.db_manager:
                        try:
                            user_info = st.session_state.db_manager.get_user(did_input)
                            if user_info:
                                st.success("👤 User found in MongoDB Atlas database")
                            else:
                                st.info("🔍 User not found in Atlas database")
                        except Exception as e:
                            st.error(f"Atlas query failed: {e}")
                    else:
                        st.error("❌ Cannot authenticate - MongoDB Atlas not connected")
                        return

                    if not user_info:
                        SecurityManager.record_failed_attempt(did_input, st.session_state.db_manager)
                        st.error("❌ DID not registered in Atlas database")
                        log_activity(did_input, "login_failed", "DID not found in Atlas", "failure")
                        return

                    # Get public key (decrypt if needed)
                    if user_info.get('pub_key_encrypted', False):
                        pub_key = safe_decrypt_data(st.session_state.server_priv_key, user_info['pub_key'], True)
                    else:
                        pub_key = user_info['pub_key']

                    # Generate challenge
                    challenge = f"{time.time()}_{did_input}_{secrets.token_hex(8)}"

                    # Create and verify ZKP
                    commitment, response = create_zk_proof(priv_key_input, challenge)

                    if verify_zk_proof(pub_key, challenge, commitment, response):
                        st.session_state.session = did_input
                        st.session_state.session_start = datetime.now()
                        SecurityManager.clear_failed_attempts(did_input)

                        # Update login stats in Atlas
                        if st.session_state.db_connected and st.session_state.db_manager:
                            try:
                                st.session_state.db_manager.update_user_login(did_input)
                            except Exception as e:
                                logger.warning(f"Failed to update login stats: {e}")

                        log_activity(did_input, "login", "ZKP authentication successful via Atlas")

                        st.markdown('<div class="success-box">', unsafe_allow_html=True)
                        st.success("✅ Authentication Successful!")
                        st.success("☁️ Login recorded in MongoDB Atlas")
                        st.success("🌍 Welcome back to your cloud-stored identity!")
                        st.markdown('</div>', unsafe_allow_html=True)

                        time.sleep(2)
                        rerun_app()
                    else:
                        SecurityManager.record_failed_attempt(did_input, st.session_state.db_manager)
                        st.error("❌ ZKP Verification Failed")
                        log_activity(did_input, "login_failed", "ZKP verification failed", "failure")

                except ZKPError as e:
                    SecurityManager.record_failed_attempt(did_input, st.session_state.db_manager)
                    st.error(f"❌ ZKP Error: {e}")
                    log_activity(did_input, "login_failed", f"ZKP error: {e}", "failure")
                except Exception as e:
                    SecurityManager.record_failed_attempt(did_input, st.session_state.db_manager)
                    st.error(f"❌ Authentication failed: {e}")
                    log_activity(did_input, "login_failed", f"Error: {e}", "failure")

    with col2:
        st.subheader("☁️ Atlas Authentication")
        st.markdown("""
        **Cloud Database Login:**
        - 🔍 Searches MongoDB Atlas
        - ☁️ Global accessibility  
        - 📊 Records login statistics
        - 🔄 Persistent across devices

        **Security Features:**
        - Zero-Knowledge Proof authentication
        - Account lockout protection
        - Session timeout management
        - All activity logged to Atlas

        **Atlas Status:**
        """)

        if st.session_state.db_connected:
            st.success("🟢 Atlas Connected")
            st.text("Ready for authentication")
        else:
            st.error("🔴 Atlas Offline")
            st.text("Check internet connection")

        if did_input and 'failed_attempts' in st.session_state:
            attempts = st.session_state.failed_attempts.get(did_input, 0)
            if attempts > 0:
                st.warning(f"⚠️ Failed attempts: {attempts}/3")

def render_dashboard():
    """Dashboard with Atlas data"""
    st.header("📊 Cloud Dashboard")

    if not st.session_state.session:
        st.warning("🔒 Please log in first")
        return

    if SecurityManager.is_session_expired():
        st.error("⏰ Session expired")
        st.session_state.session = None
        rerun_app()
        return

    st.success("☁️ Data loaded from MongoDB Atlas cloud database")

    tab1, tab2, tab3, tab4 = st.tabs(["📈 Analytics", "📋 Logs", "👥 Users", "☁️ Atlas"])

    with tab1:
        st.subheader("System Analytics from Atlas")

        # Get logs from Atlas database
        logs = []
        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                logs = st.session_state.db_manager.get_logs(limit=500)
                st.info("📊 Analytics from MongoDB Atlas cloud database")
            except Exception as e:
                st.error(f"Atlas query failed: {e}")

        if logs:
            df = pd.DataFrame(logs)

            col1, col2 = st.columns(2)
            with col1:
                if PLOTLY_AVAILABLE:
                    action_counts = df['action'].value_counts()
                    fig = px.pie(values=action_counts.values, names=action_counts.index, 
                               title="User Actions (from Atlas)")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.bar_chart(df['action'].value_counts())

            with col2:
                status_counts = df['status'].value_counts()
                if PLOTLY_AVAILABLE:
                    fig2 = px.bar(x=status_counts.index, y=status_counts.values, 
                                title="Authentication Status (from Atlas)")
                    st.plotly_chart(fig2, use_container_width=True)
                else:
                    st.bar_chart(status_counts)
        else:
            st.info("No activity data available from Atlas")

    with tab2:
        st.subheader("Activity Logs from Atlas")

        # Log filtering
        col1, col2, col3 = st.columns(3)
        with col1:
            log_limit = st.selectbox("Entries to show", [50, 100, 200, 500], index=1)
        with col2:
            action_filter = st.selectbox("Filter by action", ["All", "login", "logout", "registration", "login_failed"])
        with col3:
            if st.button("🗑️ Clear Atlas Logs"):
                if st.session_state.db_connected and st.session_state.db_manager:
                    st.session_state.db_manager.clear_logs()
                    st.success("Atlas logs cleared!")
                    rerun_app()

        # Get filtered logs from Atlas
        logs = []
        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                action = None if action_filter == "All" else action_filter
                logs = st.session_state.db_manager.get_logs(limit=log_limit, action=action)
                st.info(f"📋 Showing {len(logs)} logs from MongoDB Atlas")
            except Exception as e:
                st.error(f"Failed to load logs from Atlas: {e}")

        if logs:
            df = pd.DataFrame(logs)
            st.dataframe(df, use_container_width=True)

            csv = df.to_csv(index=False)
            st.download_button("📥 Export Atlas Logs", csv, "atlas_logs.csv", "text/csv")
        else:
            st.info("No logs available from Atlas")

    with tab3:
        st.subheader("Users from Atlas Database")

        users = []
        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                users = st.session_state.db_manager.get_all_users()
                st.info("👥 User data from MongoDB Atlas cloud database")
            except Exception as e:
                st.error(f"Failed to load users from Atlas: {e}")

        if users:
            user_data = []
            for user in users:
                pub_encrypted = user.get('pub_key_encrypted', False)
                rsa_encrypted = user.get('rsa_encrypted', False)
                encryption_status = "🔐" if (pub_encrypted or rsa_encrypted) else "🔓"

                last_login = user.get('last_login', 'Never')
                if isinstance(last_login, datetime):
                    last_login = last_login.strftime('%Y-%m-%d %H:%M')

                user_data.append({
                    'DID': user['did'][:50] + '...' if len(user['did']) > 50 else user['did'],
                    'Created': user['created'].strftime('%Y-%m-%d %H:%M') if isinstance(user['created'], datetime) else str(user['created']),
                    'Last Login': last_login,
                    'Login Count': user.get('login_count', 0),
                    'Encryption': encryption_status
                })

            df = pd.DataFrame(user_data)
            st.dataframe(df, use_container_width=True)

            st.metric("Total Users in Atlas", len(users))

            # Export users
            csv = df.to_csv(index=False)
            st.download_button("📥 Export Atlas Users", csv, "atlas_users.csv", "text/csv")
        else:
            st.info("No users found in Atlas database")

    with tab4:
        st.subheader("MongoDB Atlas Management")

        if st.session_state.db_connected:
            st.success("✅ Connected to MongoDB Atlas")

            # Atlas stats
            if st.session_state.db_manager:
                try:
                    stats = st.session_state.db_manager.get_user_stats()

                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Users", stats.get('total_users', 0))
                    with col2:
                        st.metric("Recent Registrations (24h)", stats.get('recent_registrations', 0))
                    with col3:
                        st.metric("Active Users (7d)", stats.get('active_users', 0))

                except Exception as e:
                    st.error(f"Failed to get Atlas stats: {e}")

            # Connection info
            st.info("**MongoDB Atlas Cluster:**")
            st.text("• Cluster: Cluster0 (dp9isnx)")  
            st.text("• Database: did_identity_system")
            st.text("• Region: Cloud hosted")
            st.text("• Status: Connected")

            # Atlas benefits
            st.markdown("""
            **Atlas Benefits:**
            - 🌍 Global accessibility
            - 🔒 Enterprise security  
            - 📊 Built-in monitoring
            - 🔄 Automatic backups
            - ⚡ High performance
            """)

        else:
            st.error("❌ Atlas not connected")
            st.text("Check internet connection and credentials")

def main():
    """Main function"""
    initialize_session_state()

    # Session timeout check
    if st.session_state.session and SecurityManager.is_session_expired():
        st.warning("⏰ Session expired")
        st.session_state.session = None

    render_header()
    render_sidebar()

    tab1, tab2, tab3, tab4 = st.tabs(["👤 Register", "🔐 Login", "📊 Dashboard", "☁️ About"])

    with tab1:
        render_registration()

    with tab2:
        render_login()

    with tab3:
        render_dashboard()

    with tab4:
        st.header("☁️ MongoDB Atlas Integration")
        st.markdown("""
        ## 🌍 Cloud-Powered Decentralized Identity System

        ### ✅ **MongoDB Atlas Benefits:**
        - **🌍 Global Access**: Login from anywhere in the world
        - **☁️ Cloud Storage**: No local database setup required
        - **🔒 Enterprise Security**: Bank-level data protection
        - **⚡ High Performance**: Fast queries and responses
        - **🔄 Automatic Backups**: Never lose your data
        - **📈 Scalability**: Grows with your user base

        ### 🚀 **Ready to Use:**
        Your system is now connected to MongoDB Atlas cloud database:
        - **Cluster**: Cluster0 (dp9isnx.mongodb.net)
        - **Database**: did_identity_system
        - **Collections**: users, logs

        ### 🔐 **Security Features:**
        - **Encrypted connections** (TLS/SSL)
        - **Secure authentication** with credentials
        - **Data encryption** options for sensitive information
        - **Access logging** for audit trails

        ### 📊 **Real-Time Analytics:**
        - User registration trends
        - Login patterns and frequency  
        - System usage statistics
        - Security event monitoring

        ### 🎯 **User Experience:**
        1. **Register once** → Stored permanently in Atlas
        2. **Login anywhere** → Access from any device/location
        3. **Never lose data** → Cloud-based persistence
        4. **View analytics** → Real-time insights from Atlas

        ### 💡 **Technical Stack:**
        - **Frontend**: Streamlit web application
        - **Database**: MongoDB Atlas (cloud)
        - **Authentication**: Zero-Knowledge Proofs
        - **Encryption**: RSA + AES hybrid options
        - **Identity**: W3C DID standards

        **Your DID system is now enterprise-ready with MongoDB Atlas!** 🎉
        """)

if __name__ == "__main__":
    main()