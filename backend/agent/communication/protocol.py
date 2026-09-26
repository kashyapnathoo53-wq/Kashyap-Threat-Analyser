import json
import struct
import sys
from typing import Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field

class MessageType(str, Enum):
    SCAN_REQUEST = "SCAN_REQUEST"
    SCAN_RESPONSE = "SCAN_RESPONSE"
    SNAPSHOT_LIST_REQUEST = "SNAPSHOT_LIST_REQUEST"
    SNAPSHOT_LIST_RESPONSE = "SNAPSHOT_LIST_RESPONSE"
    SNAPSHOT_GET_REQUEST = "SNAPSHOT_GET_REQUEST"
    SNAPSHOT_GET_RESPONSE = "SNAPSHOT_GET_RESPONSE"
    STATUS_REQUEST = "STATUS_REQUEST"
    STATUS_RESPONSE = "STATUS_RESPONSE"
    ERROR_RESPONSE = "ERROR_RESPONSE"

class AgentMessage(BaseModel):
    type: MessageType
    request_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

def create_response(msg_type: MessageType, payload: Dict[str, Any], request_id: Optional[str] = None) -> AgentMessage:
    return AgentMessage(
        type=msg_type,
        request_id=request_id,
        payload=payload,
        error=None
    )

def create_error_response(error: str, request_id: Optional[str] = None) -> AgentMessage:
    return AgentMessage(
        type=MessageType.ERROR_RESPONSE,
        request_id=request_id,
        payload={},
        error=error
    )

def read_native_message() -> Optional[Dict[str, Any]]:
    """Reads a message from standard input formatted for Chrome/Edge Native Messaging (32-bit length prefix)."""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None
    message_length = struct.unpack("@I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_native_message(message: Dict[str, Any]):
    """Sends a message to standard output formatted for Chrome/Edge Native Messaging."""
    encoded_content = json.dumps(message).encode("utf-8")
    encoded_length = struct.pack("@I", len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()
