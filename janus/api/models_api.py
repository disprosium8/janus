from pydantic import BaseModel, Field, RootModel
from typing import List, Optional, Union


class AddEndpointRequest(BaseModel):
    type: int
    name: str
    url: str
    edge_type: Optional[int] = None
    public_url: Optional[str] = None


class SessionRequest(BaseModel):
    instances: List[Union[dict, str]]
    image: str
    profile: str
    constraints: Optional[dict] = dict()
    arguments: Optional[str] = None
    remove_container: Optional[bool] = False
    kwargs: Optional[dict] = dict()
    overrides: Optional[dict] = dict()


# Helper for list of requests
class SessionRequestList(RootModel):
    root: List[SessionRequest]


class ProfileRequest(BaseModel):
    name: Optional[str] = None
    settings: dict


class ExecRequest(BaseModel):
    Cmd: List[str]
    node: str
    container: str
    start: Optional[bool] = False
    attach: Optional[bool] = True
    tty: Optional[bool] = False


class AuthRequest(BaseModel):
    users: List[str]
    groups: List[str]


# Query Models for Flask-OpenAPI3
class ActiveQuery(BaseModel):
    fields: Optional[str] = Field(
        None, description="Comma separated list of fields to return"
    )


class LogQuery(BaseModel):
    timestamps: Optional[bool] = Field(False, description="Include timestamps in logs")
    stderr: Optional[bool] = Field(True, description="Include stderr in logs")
    stdout: Optional[bool] = Field(True, description="Include stdout in logs")
    since: Optional[int] = Field(0, description="Return logs since this timestamp")
    tail: Optional[int] = Field(
        100, description="Number of lines to return from the end of the log"
    )


class InterfaceQuery(BaseModel):
    interface: Optional[str] = Field(None, description="Network interface name")
    container: Optional[str] = Field(None, description="Container ID")


class TuneRequest(BaseModel):
    config: dict


class NodeQuery(BaseModel):
    refresh: Optional[bool] = Field(False, description="Refresh nodes from backends")


class ProfileQuery(BaseModel):
    refresh: Optional[bool] = Field(False, description="Refresh profiles from files")
    reset: Optional[bool] = Field(False, description="Reset database tables")


# Path Models for Flask-OpenAPI3
class ActivePath(BaseModel):
    aid: Optional[int] = Field(None, description="Active session ID")


class LogPath(BaseModel):
    aid: int = Field(..., description="Active session ID")
    nname: str = Field(..., description="Node name")


class NodePath(BaseModel):
    node: Optional[str] = Field(None, description="Node name")
    id: Optional[int] = Field(None, description="Node ID")


class ImagePath(BaseModel):
    name: Optional[str] = Field(None, description="Image name")


class ProfileResourcePath(BaseModel):
    resource: str = Field(..., description="Resource type (e.g., host, net, vol, qos)")


class ProfileFullByPath(BaseModel):
    resource: str = Field(..., description="Resource type")
    rname: str = Field(..., description="Profile name")


class AuthPath(BaseModel):
    resource: str = Field(..., description="Resource type")
    rid: Optional[int] = Field(None, description="Auth ID")
    rname: Optional[str] = Field(None, description="Auth name")
