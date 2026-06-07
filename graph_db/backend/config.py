import os

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

USERS_DB = {
    "analyst": {
        "username": "analyst",
        # bcrypt hash of "password"
        "password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXe.P6GzuY6H0SDvVME8hZ0uIBTzFFN7Gi",
        "role": "analyst"
    },
    "admin": {
        "username": "admin",
        "password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXe.P6GzuY6H0SDvVME8hZ0uIBTzFFN7Gi",
        "role": "admin"
    }
}

AUTH_ENABLED = False
