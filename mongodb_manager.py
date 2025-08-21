import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import hashlib
import json

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, DuplicateKeyError, PyMongoError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False
    MongoClient = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    """Custom exception for database-related errors"""
    pass

class MongoDBManager:
    """MongoDB manager for the DID system"""

    def __init__(self, connection_string: str = "mongodb://localhost:27017/", db_name: str = "did_system"):
        
        self.connection_string = connection_string
        self.db_name = db_name
        self.client = None
        self.db = None
        self.connected = False

        if not PYMONGO_AVAILABLE:
            logger.error("PyMongo not available. Install with: pip install pymongo")
            raise DatabaseError("PyMongo library not installed")

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
            # Users collection indexes
            self.db.users.create_index("did", unique=True)
            self.db.users.create_index("created")

            # Logs collection indexes  
            self.db.logs.create_index([("timestamp", -1)])  # Descending for recent logs first
            self.db.logs.create_index("did")
            self.db.logs.create_index("action")
            self.db.logs.create_index("status")

            logger.info("Database indexes created successfully")

        except Exception as e:
            logger.warning(f"Failed to create indexes: {e}")

    def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info("Disconnected from MongoDB")

    def is_connected(self) -> bool:
        """Check if connected to MongoDB"""
        return self.connected and self.client is not None

    def store_user(self, did: str, user_data: Dict[str, Any]) -> bool:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            # Prepare document for storage
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
                    "source": "streamlit_app"
                }
            }

            # Insert user document
            result = self.db.users.insert_one(document)

            if result.inserted_id:
                logger.info(f"User stored successfully: {did}")
                return True
            else:
                logger.error(f"Failed to store user: {did}")
                return False

        except DuplicateKeyError:
            logger.warning(f"User already exists: {did}")
            raise DatabaseError(f"User with DID {did} already exists")
        except PyMongoError as e:
            logger.error(f"MongoDB error storing user: {e}")
            raise DatabaseError(f"Failed to store user: {e}")
        except Exception as e:
            logger.error(f"Unexpected error storing user: {e}")
            raise DatabaseError(f"Database operation failed: {e}")

    def get_user(self, did: str) -> Optional[Dict[str, Any]]:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            user_doc = self.db.users.find_one({"did": did})

            if user_doc:
                # Remove MongoDB's _id field for compatibility
                user_doc.pop('_id', None)
                logger.info(f"User retrieved successfully: {did}")
                return user_doc
            else:
                logger.info(f"User not found: {did}")
                return None

        except PyMongoError as e:
            logger.error(f"MongoDB error retrieving user: {e}")
            raise DatabaseError(f"Failed to retrieve user: {e}")

    def update_user_login(self, did: str) -> bool:
        
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
            logger.error(f"MongoDB error updating login: {e}")
            raise DatabaseError(f"Failed to update login: {e}")

    def get_all_users(self) -> List[Dict[str, Any]]:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            users = list(self.db.users.find({}, {"_id": 0}))  # Exclude _id field
            logger.info(f"Retrieved {len(users)} users")
            return users

        except PyMongoError as e:
            logger.error(f"MongoDB error retrieving users: {e}")
            raise DatabaseError(f"Failed to retrieve users: {e}")

    def store_log(self, log_entry: Dict[str, Any]) -> bool:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            # Add timestamp if not present
            if 'timestamp' not in log_entry:
                log_entry['timestamp'] = datetime.now()

            # Convert string timestamp to datetime if needed
            if isinstance(log_entry['timestamp'], str):
                log_entry['timestamp'] = datetime.strptime(log_entry['timestamp'], "%Y-%m-%d %H:%M:%S")

            result = self.db.logs.insert_one(log_entry)

            if result.inserted_id:
                return True
            else:
                logger.error("Failed to store log entry")
                return False

        except PyMongoError as e:
            logger.error(f"MongoDB error storing log: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error storing log: {e}")
            return False

    def get_logs(self, limit: int = 100, did: str = None, action: str = None, status: str = None) -> List[Dict[str, Any]]:
       
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            # Build filter query
            query = {}
            if did:
                query['did'] = did
            if action:
                query['action'] = action
            if status:
                query['status'] = status

            # Get logs sorted by timestamp (newest first)
            logs = list(self.db.logs.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))

            # Convert datetime back to string for compatibility
            for log in logs:
                if isinstance(log.get('timestamp'), datetime):
                    log['timestamp'] = log['timestamp'].strftime("%Y-%m-%d %H:%M:%S")

            logger.info(f"Retrieved {len(logs)} log entries")
            return logs

        except PyMongoError as e:
            logger.error(f"MongoDB error retrieving logs: {e}")
            raise DatabaseError(f"Failed to retrieve logs: {e}")

    def clear_logs(self) -> bool:
         
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            result = self.db.logs.delete_many({})
            logger.info(f"Cleared {result.deleted_count} log entries")
            return True

        except PyMongoError as e:
            logger.error(f"MongoDB error clearing logs: {e}")
            return False

    def get_user_stats(self) -> Dict[str, Any]:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            total_users = self.db.users.count_documents({})

            # Get recent registrations (last 24 hours)
            yesterday = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            recent_users = self.db.users.count_documents({"created": {"$gte": yesterday}})

            # Get users with recent activity (last 7 days)
            week_ago = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            week_ago = week_ago.replace(day=week_ago.day - 7) if week_ago.day > 7 else week_ago.replace(month=week_ago.month - 1, day=week_ago.day + 23)
            active_users = self.db.users.count_documents({"last_login": {"$gte": week_ago}})

            return {
                "total_users": total_users,
                "recent_registrations": recent_users,
                "active_users": active_users,
                "database_connected": True
            }

        except PyMongoError as e:
            logger.error(f"MongoDB error getting stats: {e}")
            return {"database_connected": False, "error": str(e)}

    def delete_user(self, did: str) -> bool:
        
        if not self.is_connected():
            raise DatabaseError("Not connected to MongoDB")

        try:
            result = self.db.users.delete_one({"did": did})

            if result.deleted_count > 0:
                logger.info(f"User deleted: {did}")
                return True
            else:
                logger.warning(f"User not found for deletion: {did}")
                return False

        except PyMongoError as e:
            logger.error(f"MongoDB error deleting user: {e}")
            return False

# Utility functions for database operations
def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data before storage"""
    return hashlib.sha256(data.encode()).hexdigest()

def validate_did_format(did: str) -> bool:
    """Validate DID format before database operations"""
    return bool(did and did.startswith("did:") and len(did) > 10)

# Database connection singleton
_db_manager = None

def get_db_manager(connection_string: str = None) -> MongoDBManager:
    """Get or create database manager instance"""
    global _db_manager

    if _db_manager is None or not _db_manager.is_connected():
        try:
            conn_str = connection_string or "mongodb://localhost:27017/"
            _db_manager = MongoDBManager(conn_str)
        except Exception as e:
            logger.error(f"Failed to create database manager: {e}")
            raise DatabaseError(f"Database initialization failed: {e}")

    return _db_manager

def test_connection(connection_string: str = "mongodb://localhost:27017/") -> bool:
    """Test MongoDB connection"""
    try:
        manager = MongoDBManager(connection_string)
        connected = manager.is_connected()
        manager.disconnect()
        return connected
    except Exception:
        return False