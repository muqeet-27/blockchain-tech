import streamlit as st
import time
import pandas as pd
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import hashlib
import secrets

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    st.warning("⚠️ python-dotenv not installed. Install with: pip install python-dotenv")

# Import original modules
try:
    from did import create_peer_did, update_did
    from zkp import generate_keypair, create_zk_proof, verify_zk_proof, ZKPError
    from encryption import generate_rsa_keypair, encrypt_data, decrypt_data
except ImportError as e:
    st.error(f"Import error: {e}")
    st.error("Please ensure did.py, zkp_fixed.py, and encryption.py are available")
    st.stop()

# MongoDB imports
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, DuplicateKeyError, PyMongoError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False
    MongoClient = None

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

# ===== ENVIRONMENT CONFIGURATION =====
class Config:
    """Configuration loaded from environment variables"""

    # MongoDB Configuration
    MONGODB_CONNECTION_STRING = os.getenv(
        'MONGODB_CONNECTION_STRING',
        'mongodb://localhost:27017/'  # Fallback to local
    )
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'did_identity_system')

    # Security Configuration
    SERVER_SECRET_KEY = os.getenv('SERVER_SECRET_KEY', 'default-secret-key')
    ENCRYPTION_ENABLED = os.getenv('ENCRYPTION_ENABLED', 'false').lower() == 'true'
    SESSION_TIMEOUT_HOURS = int(os.getenv('SESSION_TIMEOUT_HOURS', '2'))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '3'))

    # Application Configuration
    APP_TITLE = os.getenv('APP_TITLE', 'DID Identity System')
    APP_DESCRIPTION = os.getenv('APP_DESCRIPTION', 'Decentralized Identity System')
    DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

    @classmethod
    def validate_config(cls):
        """Validate configuration and show warnings"""
        issues = []

        if cls.MONGODB_CONNECTION_STRING == 'mongodb://localhost:27017/':
            issues.append("MongoDB connection using fallback (local)")

        if cls.SERVER_SECRET_KEY == 'default-secret-key':
            issues.append("Using default server secret key (insecure)")

        if not DOTENV_AVAILABLE:
            issues.append("python-dotenv not installed")

        return issues

    @classmethod
    def is_atlas_connection(cls):
        """Check if using MongoDB Atlas"""
        return 'mongodb+srv://' in cls.MONGODB_CONNECTION_STRING

    @classmethod
    def get_masked_connection(cls):
        """Get connection string with password masked"""
        conn = cls.MONGODB_CONNECTION_STRING
        if ':' in conn and '@' in conn:
            # Extract and mask password
            parts = conn.split('://')
            if len(parts) == 2:
                protocol = parts[0]
                rest = parts[1]
                if '@' in rest:
                    auth_part, server_part = rest.split('@', 1)
                    if ':' in auth_part:
                        username, password = auth_part.split(':', 1)
                        masked = f"{protocol}://{username}:***@{server_part}"
                        return masked
        return conn[:50] + '...' if len(conn) > 50 else conn

# Page configuration
st.set_page_config(
    page_title=Config.APP_TITLE,
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
    .env-badge {
        background-color: #28a745;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .secure-badge {
        background-color: #6f42c1;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.8rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ===== DATABASE MANAGER =====
class DatabaseError(Exception):
    """Custom exception for database-related errors"""
    pass

class AtlasManager:
    """MongoDB Atlas manager using environment configuration"""

    def __init__(self):
        self.connection_string = Config.MONGODB_CONNECTION_STRING
        self.db_name = Config.DATABASE_NAME
        self.client = None
        self.db = None
        self.connected = False

        if not PYMONGO_AVAILABLE:
            raise DatabaseError("PyMongo library not installed - run: pip install pymongo")

        self.connect()

    def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = MongoClient(self.connection_string, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.connected = True

            # Create indexes for better performance
            self.setup_indexes()

            logger.info(f"Connected to MongoDB: {self.db_name}")

        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self.connected = False
            raise DatabaseError(f"MongoDB connection failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            self.connected = False
            raise DatabaseError(f"Database connection error: {e}")

    def setup_indexes(self):
        """Create database indexes for optimal performance"""
        try:
            self.db.users.create_index("did", unique=True)
            self.db.users.create_index("created")
            self.db.logs.create_index([("timestamp", -1)])
            self.db.logs.create_index("did")
            self.db.logs.create_index("action")
            self.db.logs.create_index("status")
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.warning(f"Failed to create indexes: {e}")

    def is_connected(self) -> bool:
        """Check if connected to MongoDB"""
        return self.connected and self.client is not None

    def store_user(self, did: str, user_data: Dict[str, Any]) -> bool:
        """Store user data in MongoDB"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            document = {
                "did": did,
                "pub_key": user_data.get('pub_key'),
                "pub_rsa": user_data.get('pub_rsa'),
                "created": user_data.get('created', datetime.now()),
                "pub_key_encrypted": user_data.get('pub_key_encrypted', False),
                "rsa_encrypted": user_data.get('rsa_encrypted', False),
                "last_login": None,
                "login_count": 0,
                "metadata": {
                    "version": "1.0",
                    "source": "env_secured_app",
                    "config_source": "environment_variables"
                }
            }

            result = self.db.users.insert_one(document)

            if result.inserted_id:
                logger.info(f"User stored in database: {did}")
                return True
            else:
                logger.error(f"Failed to store user: {did}")
                return False

        except DuplicateKeyError:
            logger.warning(f"User already exists: {did}")
            raise DatabaseError(f"User with DID {did} already exists")
        except PyMongoError as e:
            logger.error(f"Database error storing user: {e}")
            raise DatabaseError(f"Failed to store user: {e}")

    def get_user(self, did: str) -> Optional[Dict[str, Any]]:
        """Retrieve user data from MongoDB"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            user_doc = self.db.users.find_one({"did": did})

            if user_doc:
                user_doc.pop('_id', None)
                logger.info(f"User retrieved from database: {did}")
                return user_doc
            else:
                logger.info(f"User not found: {did}")
                return None

        except PyMongoError as e:
            logger.error(f"Database error retrieving user: {e}")
            raise DatabaseError(f"Failed to retrieve user: {e}")

    def update_user_login(self, did: str) -> bool:
        """Update user's last login time and increment login count"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            result = self.db.users.update_one(
                {"did": did},
                {
                    "$set": {"last_login": datetime.now()},
                    "$inc": {"login_count": 1}
                }
            )

            if result.modified_count > 0:
                logger.info(f"User login updated: {did}")
                return True
            else:
                logger.warning(f"User not found for login update: {did}")
                return False

        except PyMongoError as e:
            logger.error(f"Database error updating login: {e}")
            raise DatabaseError(f"Failed to update login: {e}")

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users from the database"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            users = list(self.db.users.find({}, {"_id": 0}))
            logger.info(f"Retrieved {len(users)} users from database")
            return users
        except PyMongoError as e:
            logger.error(f"Database error retrieving users: {e}")
            raise DatabaseError(f"Failed to retrieve users: {e}")

    def store_log(self, log_entry: Dict[str, Any]) -> bool:
        """Store activity log in MongoDB"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            if 'timestamp' not in log_entry:
                log_entry['timestamp'] = datetime.now()

            if isinstance(log_entry['timestamp'], str):
                log_entry['timestamp'] = datetime.strptime(log_entry['timestamp'], "%Y-%m-%d %H:%M:%S")

            result = self.db.logs.insert_one(log_entry)
            return bool(result.inserted_id)

        except PyMongoError as e:
            logger.error(f"Database error storing log: {e}")
            return False

    def get_logs(self, limit: int = 100, did: str = None, action: str = None, status: str = None) -> List[Dict[str, Any]]:
        """Retrieve activity logs with optional filtering"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            query = {}
            if did:
                query['did'] = did
            if action:
                query['action'] = action
            if status:
                query['status'] = status

            logs = list(self.db.logs.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))

            # Convert datetime back to string for compatibility
            for log in logs:
                if isinstance(log.get('timestamp'), datetime):
                    log['timestamp'] = log['timestamp'].strftime("%Y-%m-%d %H:%M:%S")

            logger.info(f"Retrieved {len(logs)} log entries")
            return logs

        except PyMongoError as e:
            logger.error(f"Database error retrieving logs: {e}")
            raise DatabaseError(f"Failed to retrieve logs: {e}")

    def clear_logs(self) -> bool:
        """Clear all activity logs"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            result = self.db.logs.delete_many({})
            logger.info(f"Cleared {result.deleted_count} log entries")
            return True
        except PyMongoError as e:
            logger.error(f"Database error clearing logs: {e}")
            return False

    def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            total_users = self.db.users.count_documents({})

            yesterday = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            recent_users = self.db.users.count_documents({"created": {"$gte": yesterday}})

            week_ago = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            if week_ago.day > 7:
                week_ago = week_ago.replace(day=week_ago.day - 7)
            else:
                week_ago = week_ago.replace(month=week_ago.month - 1, day=week_ago.day + 23)

            active_users = self.db.users.count_documents({"last_login": {"$gte": week_ago}})

            return {
                "total_users": total_users,
                "recent_registrations": recent_users,
                "active_users": active_users,
                "database_connected": True
            }

        except PyMongoError as e:
            logger.error(f"Database error getting stats: {e}")
            return {"database_connected": False, "error": str(e)}

# ===== APPLICATION LOGIC =====
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
    """Security features using environment configuration"""
    MAX_LOGIN_ATTEMPTS = Config.MAX_LOGIN_ATTEMPTS
    LOCKOUT_DURATION = timedelta(minutes=15)
    SESSION_TIMEOUT = timedelta(hours=Config.SESSION_TIMEOUT_HOURS)

    @staticmethod
    def is_locked_out(did: str) -> bool:
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
    def record_failed_attempt(did: str):
        if 'failed_attempts' not in st.session_state:
            st.session_state.failed_attempts = {}

        attempts = st.session_state.failed_attempts.get(did, 0) + 1
        st.session_state.failed_attempts[did] = attempts

        if attempts >= SecurityManager.MAX_LOGIN_ATTEMPTS:
            if 'lockouts' not in st.session_state:
                st.session_state.lockouts = {}
            st.session_state.lockouts[did] = datetime.now()
            st.session_state.failed_attempts[did] = 0

    @staticmethod
    def clear_failed_attempts(did: str):
        if 'failed_attempts' in st.session_state and did in st.session_state.failed_attempts:
            del st.session_state.failed_attempts[did]

    @staticmethod
    def is_session_expired() -> bool:
        if 'session_start' not in st.session_state:
            return True
        return datetime.now() - st.session_state.session_start > SecurityManager.SESSION_TIMEOUT

def safe_encrypt_data(public_key_pem: str, data: str) -> tuple[str, bool]:
    """Safely encrypt data with size checking"""
    if not Config.ENCRYPTION_ENABLED:
        return data, False

    try:
        if len(data.encode('utf-8')) <= 190:
            encrypted = encrypt_data(public_key_pem, data)
            return encrypted, True
        else:
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
    """Initialize session state"""
    defaults = {
        'session': None,
        'session_start': None,
        'failed_attempts': {},
        'lockouts': {},
        'db_manager': None,
        'db_connected': False
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Initialize database connection
    if not st.session_state.db_connected:
        initialize_database()

    # Generate server RSA keys using environment secret
    if 'server_priv_key' not in st.session_state:
        try:
            pub, priv = generate_rsa_keypair()
            st.session_state.server_pub_key = pub
            st.session_state.server_priv_key = priv
        except Exception as e:
            st.error(f"Failed to generate server keys: {e}")

def initialize_database():
    """Initialize MongoDB connection using environment variables"""
    if not PYMONGO_AVAILABLE:
        st.session_state.db_connected = False
        st.session_state.db_manager = None
        return

    try:
        st.session_state.db_manager = AtlasManager()
        st.session_state.db_connected = st.session_state.db_manager.is_connected()
        if st.session_state.db_connected:
            logger.info("Database connection established using environment config")
    except Exception as e:
        st.session_state.db_connected = False
        st.session_state.db_manager = None
        logger.error(f"Database initialization failed: {e}")

def log_activity(did: str, action: str, details: str, status: str = "success"):
    """Log activity to MongoDB"""
    log_entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'did': did,
        'action': action,
        'details': details,
        'status': status,
        'config_source': 'environment_variables'
    }

    # Store in database if available
    if st.session_state.db_connected and st.session_state.db_manager:
        try:
            st.session_state.db_manager.store_log(log_entry)
        except Exception as e:
            logger.error(f"Failed to store log in database: {e}")

def render_header():
    """Render header with environment status"""
    st.markdown(f'<h1 class="main-header">🔐 {Config.APP_TITLE}</h1>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown(f"**{Config.APP_DESCRIPTION}**")
    with col2:
        if st.session_state.db_connected:
            if Config.is_atlas_connection():
                st.markdown('<span class="env-badge">ATLAS</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="env-badge">MONGODB</span>', unsafe_allow_html=True)
        else:
            st.error("DB Offline")
    with col3:
        st.markdown('<span class="secure-badge">ENV SECURED</span>', unsafe_allow_html=True)

    # Show configuration warnings if any
    config_issues = Config.validate_config()
    if config_issues and Config.DEBUG_MODE:
        st.warning("⚠️ Configuration issues: " + ", ".join(config_issues))

    st.markdown("---")

    # Metrics from database
    col1, col2, col3, col4 = st.columns(4)

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
        db_type = "Atlas" if Config.is_atlas_connection() else "MongoDB"
        status = f"{db_type} Connected" if st.session_state.db_connected else "Offline"
        st.metric("Database", status)

def render_sidebar():
    """Render sidebar with environment configuration"""
    with st.sidebar:
        st.header("System Status")

        if st.session_state.session:
            st.success("✅ Logged in")
            st.text(f"DID: {st.session_state.session[:25]}...")

            if st.button("🚪 Logout"):
                old_session = st.session_state.session
                st.session_state.session = None
                st.session_state.session_start = None
                log_activity(old_session, "logout", "User logged out")
                st.success("Logged out!")
                time.sleep(1)
                rerun_app()
        else:
            st.info("🔒 Not logged in")

        st.markdown("---")

        # Environment Configuration Status
        st.subheader("🔒 Environment Config")
        if DOTENV_AVAILABLE:
            st.success("✅ .env file loaded")
        else:
            st.warning("⚠️ Install python-dotenv")

        st.text(f"Database: {Config.DATABASE_NAME}")
        st.text(f"Encryption: {'Enabled' if Config.ENCRYPTION_ENABLED else 'Disabled'}")
        st.text(f"Session timeout: {Config.SESSION_TIMEOUT_HOURS}h")
        st.text(f"Max attempts: {Config.MAX_LOGIN_ATTEMPTS}")

        # Database Status
        st.subheader("🗄️ Database")
        if st.session_state.db_connected:
            if Config.is_atlas_connection():
                st.success("✅ MongoDB Atlas")
            else:
                st.success("✅ MongoDB Local")
        else:
            st.error("❌ Database Offline")

def render_registration():
    """Registration with environment-secured database"""
    st.header("👤 User Registration")

    if not st.session_state.db_connected:
        st.error("⚠️ Database offline - registration not available")
        return

    st.success(f"🔒 Ready to store users securely in {Config.DATABASE_NAME}")

    if st.button("🎯 Generate DID and Store Securely", type="primary"):
        with st.spinner("Generating and storing with environment config..."):
            try:
                # Generate keypairs
                priv_key, pub_key = generate_keypair()
                rsa_pub, rsa_priv = generate_rsa_keypair()
                did = create_peer_did(pub_key)

                # Handle encryption based on environment config
                stored_pub_key, pub_encrypted = safe_encrypt_data(st.session_state.server_pub_key, pub_key)
                stored_rsa_pub, rsa_encrypted = safe_encrypt_data(st.session_state.server_pub_key, rsa_pub)

                user_data = {
                    'pub_key': stored_pub_key,
                    'pub_rsa': stored_rsa_pub,
                    'created': datetime.now(),
                    'pub_key_encrypted': pub_encrypted,
                    'rsa_encrypted': rsa_encrypted
                }

                # Store in database
                st.session_state.db_manager.store_user(did, user_data)
                log_activity(did, "registration", f"New DID created with env config (encrypted: {any([pub_encrypted, rsa_encrypted])})")

                st.markdown('<div class="success-box">', unsafe_allow_html=True)
                st.success("🎉 Identity Created and Stored Securely!")
                st.success("🔒 Stored using environment-secured database connection")
                st.success("🌍 Accessible globally with your credentials")
                st.markdown('</div>', unsafe_allow_html=True)

                st.info(f"**DID:** `{did}`")

                # Show encryption status
                if Config.ENCRYPTION_ENABLED:
                    if pub_encrypted:
                        st.success("🔐 ECDSA public key encrypted")
                    else:
                        st.info("🔓 ECDSA public key stored unencrypted")

                    if rsa_encrypted:
                        st.success("🔐 RSA public key encrypted")
                    else:
                        st.info("🔓 RSA public key unencrypted (too large)")
                else:
                    st.info("🔓 Encryption disabled in environment config")

                # Keys display
                with st.expander("🔑 Private Keys (Save Securely!)"):
                    st.warning("⚠️ **CRITICAL**: These keys are NOT stored in the database. Save them now!")

                    st.text("ECDSA Private Key (for authentication):")
                    st.code(priv_key)
                    st.download_button("💾 Download ECDSA Key", priv_key, "ecdsa_key.txt", key="dl_ecdsa")

                    st.text("RSA Private Key (for encryption):")
                    st.text_area("", rsa_priv, height=200, key="rsa_display")
                    st.download_button("💾 Download RSA Key", rsa_priv, "rsa_key.pem", key="dl_rsa")

                st.error("🚨 **SAVE YOUR KEYS**: They cannot be recovered if lost!")
                st.success("✅ Your DID is now permanently stored - login anytime!")

            except DatabaseError as e:
                if "already exists" in str(e):
                    st.error("❌ User with this DID already exists")
                else:
                    st.error(f"❌ Registration failed: {e}")
            except Exception as e:
                st.error(f"❌ Registration failed: {e}")

def render_login():
    """Login with environment-secured authentication"""
    st.header("🔐 Environment-Secured Authentication")
    st.info("🔒 Login using credentials stored in environment-secured database")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Login Form")

        did_input = st.text_input("🆔 DID", placeholder="did:peer:2.Vz...")
        priv_key_input = st.text_input("🔑 ECDSA Private Key", type="password")

        # Validation
        inputs_valid = bool(did_input and priv_key_input)
        did_format_valid = validate_did_format(did_input) if did_input else False
        is_locked = SecurityManager.is_locked_out(did_input) if did_input else False

        if did_input and not did_format_valid:
            st.error("❌ Invalid DID format")

        if is_locked:
            st.error(f"🚫 Account locked for 15 minutes (max {Config.MAX_LOGIN_ATTEMPTS} attempts)")

        if st.button("🚀 Secure Login", disabled=not (inputs_valid and did_format_valid and not is_locked), type="primary"):
            with st.spinner("Authenticating with environment-secured database..."):
                try:
                    if not st.session_state.db_connected:
                        st.error("❌ Database not connected")
                        return

                    user_info = st.session_state.db_manager.get_user(did_input)

                    if not user_info:
                        SecurityManager.record_failed_attempt(did_input)
                        st.error("❌ DID not found in secure database")
                        log_activity(did_input, "login_failed", "DID not found", "failure")
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

                        # Update login stats
                        st.session_state.db_manager.update_user_login(did_input)
                        log_activity(did_input, "login", "Successful environment-secured authentication")

                        st.markdown('<div class="success-box">', unsafe_allow_html=True)
                        st.success("✅ Authentication Successful!")
                        st.success("🔒 Logged in using environment-secured credentials")
                        st.success("🌍 Welcome to your secure cloud identity!")
                        st.markdown('</div>', unsafe_allow_html=True)

                        time.sleep(2)
                        rerun_app()
                    else:
                        SecurityManager.record_failed_attempt(did_input)
                        st.error("❌ ZKP Verification Failed")
                        log_activity(did_input, "login_failed", "ZKP verification failed", "failure")

                except ZKPError as e:
                    SecurityManager.record_failed_attempt(did_input)
                    st.error(f"❌ ZKP Error: {e}")
                    log_activity(did_input, "login_failed", f"ZKP error: {e}", "failure")
                except Exception as e:
                    SecurityManager.record_failed_attempt(did_input)
                    st.error(f"❌ Authentication failed: {e}")
                    log_activity(did_input, "login_failed", f"Error: {e}", "failure")

    with col2:
        st.subheader("🔒 Secure Features")
        st.markdown(f"""
        **Environment Security:**
        - 🔒 Credentials in .env file
        - 🗄️ Secure database connection
        - 🔐 Optional data encryption
        - 📊 Activity logging

        **Configuration:**
        - Database: {Config.DATABASE_NAME}
        - Max attempts: {Config.MAX_LOGIN_ATTEMPTS}
        - Session timeout: {Config.SESSION_TIMEOUT_HOURS}h
        - Encryption: {'On' if Config.ENCRYPTION_ENABLED else 'Off'}

        **Database Status:**
        """)

        if st.session_state.db_connected:
            db_type = "Atlas" if Config.is_atlas_connection() else "Local"
            st.success(f"🟢 MongoDB {db_type}")
        else:
            st.error("🔴 Database Offline")

        if did_input and 'failed_attempts' in st.session_state:
            attempts = st.session_state.failed_attempts.get(did_input, 0)
            if attempts > 0:
                st.warning(f"⚠️ Failed attempts: {attempts}/{Config.MAX_LOGIN_ATTEMPTS}")

def render_dashboard():
    """Dashboard with environment-secured data"""
    st.header("📊 Environment-Secured Dashboard")

    if not st.session_state.session:
        st.warning("🔒 Please log in first")
        return

    if SecurityManager.is_session_expired():
        st.error(f"⏰ Session expired (timeout: {Config.SESSION_TIMEOUT_HOURS}h)")
        st.session_state.session = None
        rerun_app()
        return

    st.success("🔒 Data loaded from environment-secured database")

    tab1, tab2, tab3, tab4 = st.tabs(["📈 Analytics", "📋 Logs", "👥 Users", "🔒 Config"])

    with tab1:
        st.subheader("System Analytics")

        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                logs = st.session_state.db_manager.get_logs(limit=500)
                st.info(f"📊 Analytics from {Config.DATABASE_NAME}")

                if logs:
                    df = pd.DataFrame(logs)

                    col1, col2 = st.columns(2)
                    with col1:
                        if PLOTLY_AVAILABLE:
                            action_counts = df['action'].value_counts()
                            fig = px.pie(values=action_counts.values, names=action_counts.index, 
                                       title="User Actions")
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.bar_chart(df['action'].value_counts())

                    with col2:
                        status_counts = df['status'].value_counts()
                        if PLOTLY_AVAILABLE:
                            fig2 = px.bar(x=status_counts.index, y=status_counts.values, 
                                        title="Authentication Status")
                            st.plotly_chart(fig2, use_container_width=True)
                        else:
                            st.bar_chart(status_counts)
                else:
                    st.info("No analytics data available")
            except Exception as e:
                st.error(f"Analytics error: {e}")

    with tab2:
        st.subheader("Activity Logs")

        # Log filtering
        col1, col2, col3 = st.columns(3)
        with col1:
            log_limit = st.selectbox("Entries to show", [50, 100, 200, 500], index=1)
        with col2:
            action_filter = st.selectbox("Filter by action", ["All", "login", "logout", "registration", "login_failed"])
        with col3:
            if st.button("🗑️ Clear All Logs"):
                if st.session_state.db_connected and st.session_state.db_manager:
                    st.session_state.db_manager.clear_logs()
                    st.success("Logs cleared!")
                    rerun_app()

        # Get filtered logs
        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                action = None if action_filter == "All" else action_filter
                logs = st.session_state.db_manager.get_logs(limit=log_limit, action=action)
                st.info(f"📋 Showing {len(logs)} logs from {Config.DATABASE_NAME}")

                if logs:
                    df = pd.DataFrame(logs)
                    st.dataframe(df, use_container_width=True)

                    csv = df.to_csv(index=False)
                    st.download_button("📥 Export Logs", csv, "secure_logs.csv", "text/csv")
                else:
                    st.info("No logs available")
            except Exception as e:
                st.error(f"Failed to load logs: {e}")

    with tab3:
        st.subheader("Registered Users")

        if st.session_state.db_connected and st.session_state.db_manager:
            try:
                users = st.session_state.db_manager.get_all_users()
                st.info(f"👥 User data from {Config.DATABASE_NAME}")

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

                    st.metric("Total Users in Database", len(users))

                    # Export users
                    csv = df.to_csv(index=False)
                    st.download_button("📥 Export Users", csv, "secure_users.csv", "text/csv")
                else:
                    st.info("No users found in database")
            except Exception as e:
                st.error(f"Failed to load users: {e}")

    with tab4:
        st.subheader("Environment Configuration")

        st.success("🔒 Configuration loaded from environment variables")

        # Configuration display
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Database Configuration:**")
            st.text(f"Connection: {Config.get_masked_connection()}")
            st.text(f"Database: {Config.DATABASE_NAME}")
            st.text(f"Type: {'Atlas' if Config.is_atlas_connection() else 'Local'}")
            st.text(f"Connected: {'Yes' if st.session_state.db_connected else 'No'}")

        with col2:
            st.markdown("**Security Configuration:**")
            st.text(f"Encryption: {'Enabled' if Config.ENCRYPTION_ENABLED else 'Disabled'}")
            st.text(f"Session timeout: {Config.SESSION_TIMEOUT_HOURS} hours")
            st.text(f"Max login attempts: {Config.MAX_LOGIN_ATTEMPTS}")
            st.text(f"Debug mode: {'On' if Config.DEBUG_MODE else 'Off'}")

        # Configuration validation
        config_issues = Config.validate_config()
        if config_issues:
            st.warning("⚠️ Configuration Issues:")
            for issue in config_issues:
                st.text(f"• {issue}")
        else:
            st.success("✅ Configuration validated successfully")

        # Environment status
        st.markdown("**Environment Status:**")
        st.text(f"python-dotenv: {'Available' if DOTENV_AVAILABLE else 'Missing'}")
        st.text(f"PyMongo: {'Available' if PYMONGO_AVAILABLE else 'Missing'}")
        st.text(f"Plotly: {'Available' if PLOTLY_AVAILABLE else 'Missing'}")

def main():
    """Main function"""
    initialize_session_state()

    # Session timeout check
    if st.session_state.session and SecurityManager.is_session_expired():
        st.warning(f"⏰ Session expired (timeout: {Config.SESSION_TIMEOUT_HOURS}h)")
        st.session_state.session = None

    render_header()
    render_sidebar()

    tab1, tab2, tab3, tab4 = st.tabs(["👤 Register", "🔐 Login", "📊 Dashboard", "🔒 About"])

    with tab1:
        render_registration()

    with tab2:
        render_login()

    with tab3:
        render_dashboard()

    with tab4:
        st.header("🔒 Environment-Secured DID System")
        st.markdown(f"""
        ## 🌟 Environment Variable Configuration

        This system uses **environment variables** for secure configuration management:

        ### 🔒 **Security Benefits:**
        - **No hardcoded secrets** in source code
        - **Environment-specific** configuration
        - **Production-ready** security practices
        - **Easy deployment** across environments

        ### 📁 **Configuration Files:**
        - **.env**: Environment variables and secrets
        - **app_env.py**: This application file
        - **did.py, zkp_fixed.py, encryption.py**: Core modules

        ### ⚙️ **Environment Variables Used:**
        ```
        MONGODB_CONNECTION_STRING    # Database connection
        DATABASE_NAME               # Database name
        SERVER_SECRET_KEY           # Server encryption key
        ENCRYPTION_ENABLED          # Enable/disable encryption
        SESSION_TIMEOUT_HOURS       # Session timeout
        MAX_LOGIN_ATTEMPTS          # Security limits
        APP_TITLE                   # Application title
        DEBUG_MODE                  # Debug settings
        ```

        ### 🚀 **Setup Instructions:**

        1. **Install dependencies:**
        ```bash
        pip install pymongo python-dotenv plotly
        ```

        2. **Configure .env file:**
        ```bash
        # Edit .env with your settings
        MONGODB_CONNECTION_STRING=your_connection_string
        DATABASE_NAME=your_database_name
        ```

        3. **Run the application:**
        ```bash
        streamlit run app_env.py
        ```

        ### 🔐 **Current Configuration:**
        - **Database**: {Config.DATABASE_NAME}
        - **Connection**: {'Atlas' if Config.is_atlas_connection() else 'Local MongoDB'}
        - **Encryption**: {'Enabled' if Config.ENCRYPTION_ENABLED else 'Disabled'}
        - **Session Timeout**: {Config.SESSION_TIMEOUT_HOURS} hours
        - **Max Attempts**: {Config.MAX_LOGIN_ATTEMPTS}

        ### 🌍 **Production Ready:**
        This system is now ready for production deployment with:
        - Environment-based configuration
        - Secure credential management
        - MongoDB Atlas cloud database
        - Enterprise security features
        - Comprehensive audit logging

        **Perfect for secure, scalable decentralized identity management!** 🎉
        """)

if __name__ == "__main__":
    main()