import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from openenv.core.env_server import create_fastapi_app
from environment import SocAnalystEnvironment

app = create_fastapi_app(SocAnalystEnvironment)
