import logging
from functools import wraps
from typing import Optional

from flask import request, jsonify, abort
from flask_httpauth import HTTPBasicAuth
from flask_openapi3 import APIBlueprint, Tag
from pydantic import ValidationError, BaseModel
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
from werkzeug.security import check_password_hash

from janus.api.db import QueryUser
from janus.api.models import Node, ContainerProfile, NetworkProfile, VolumeProfile
from janus.api.models_api import (
    AddEndpointRequest,
    SessionRequestList,
    ProfileRequest,
    ExecRequest,
    LogQuery,
    ActiveQuery,
    LogPath,
    ActivePath,
    NodePath,
    ImagePath,
    ProfileResourcePath,
    ProfileFullByPath,
    AuthPath,
)
from janus.api.constants import Constants
from janus import settings
from janus.settings import cfg

# Basic auth
httpauth = HTTPBasicAuth()
log = logging.getLogger(__name__)

tag = Tag(
    name="janus/controller",
    description="Operations for Janus on-demand container provisioning",
)
api_prefix = getattr(settings, "API_PREFIX", "") or ""
api = APIBlueprint(
    "controller", __name__, url_prefix=api_prefix + "/janus/controller", abp_tags=[tag]
)


@httpauth.error_handler
def auth_error(status):
    return jsonify(error="Unauthorized"), status


@httpauth.verify_password
def verify_password(username, password):
    users = cfg.get_users()
    if username in users and check_password_hash(users.get(username), password):
        return username


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not httpauth.current_user() == "admin":
            abort(403)
        return f(*args, **kwargs)

    return wrapper


def get_authinfo(request):
    api_user = httpauth.current_user()
    if api_user == "admin":
        user = request.args.get("user", None)
        group = request.args.get("group", None)
    else:
        user = api_user
        group = None
    log.debug(f"User: {user}, Group: {group}")
    return (user, group)


@api.get(
    "/active/<int:aid>/logs/<path:nname>",
    summary="Display logs for a specific active session and node.",
)
@httpauth.login_required
def get_logs(path: LogPath, query: LogQuery):
    """
    Display logs for a specific active session and node.
    """
    aid = path.aid
    nname = path.nname
    (user, group) = get_authinfo(request)
    quser = QueryUser()
    q = quser.query_builder(user, group, {"id": aid})
    dbase = cfg.db
    table = dbase.get_table("active")
    if q and aid:
        res = dbase.get(table, query=q)
        if not res:
            return {"error": "Not found"}, 404
        if nname:
            try:
                ts = query.timestamps
                stderr = query.stderr
                stdout = query.stdout
                since = query.since
                tail = query.tail
                svc = res["services"][nname]
                cid = svc[0]["container_id"]
                n = Node(id=svc[0]["node_id"], name=nname)
                handler = cfg.sm.get_handler(nname=nname)
                return handler.get_logs(n, cid, since, stderr, stdout, tail, ts)
            except Exception as e:
                import traceback

                traceback.print_exc()
                return {"error": f"Could not retrieve container logs: {e}"}, 500
    return {"error": "Not found"}, 404


@api.get("/active", summary="Get all active sessions")
@httpauth.login_required
def get_active(query: ActiveQuery):
    """
    Get active sessions
    """
    (user, group) = get_authinfo(request)
    quser = QueryUser()
    q = quser.query_builder(user, group, {})
    fields = query.fields
    dbase = cfg.db
    table = dbase.get_table("active")

    if q:
        res = dbase.search(table, query=q)
    else:
        res = dbase.all(table)

    if fields:
        ret = list()
        for r in res:
            if not r:
                continue
            ret.append({k: v for k, v in r.items() if k in fields.split(",")})
        return jsonify(ret)
    return jsonify(res)


@api.get("/active/<int:aid>", summary="Get a specific active session")
@httpauth.login_required
def get_active_by_id(path: ActivePath, query: ActiveQuery):
    """
    Get a specific active session
    """
    aid = path.aid
    (user, group) = get_authinfo(request)
    quser = QueryUser()
    q = quser.query_builder(user, group, {"id": aid})
    fields = query.fields
    dbase = cfg.db
    table = dbase.get_table("active")

    if q and aid:
        res = dbase.get(table, query=q)
        if not res:
            return {"error": "Not found"}, 404
        if fields:
            return jsonify({k: v for k, v in res.items() if k in fields.split(",")})
        else:
            return jsonify(res)
    return {"error": "Not found"}, 404


@api.get("/nodes", summary="Get nodes")
@httpauth.login_required
def get_nodes():
    """
    List all nodes.
    """
    (user, group) = get_authinfo(request)
    dbase = cfg.db
    table = dbase.get_table("nodes")
    return jsonify(dbase.all(table))


@api.get("/nodes/name/<node>", summary="Get node by name")
@api.get("/nodes/id/<int:id>", summary="Get node by ID")
@httpauth.login_required
def get_node_by_id_or_name(path: NodePath):
    node = path.node
    node_id = path.id
    dbase = cfg.db
    table = dbase.get_table("nodes")
    if node:
        res = dbase.get(table, name=node)
    else:
        res = dbase.get(table, id=node_id)
    if not res:
        return {"error": "Not found"}, 404
    return jsonify(res)


@api.post("/nodes", summary="Add a new node")
@httpauth.login_required
@admin_required
def add_node(body: AddEndpointRequest):
    """
    Add a new Janus endpoint.
    """
    from janus.api.manager import ServiceManagerException

    try:
        req = body.model_dump()
        return jsonify(cfg.sm.add_endpoint(req))
    except ServiceManagerException as e:
        raise BadRequest(f"Adding endpoint failed: {e}")
    except Exception as e:
        raise InternalServerError(f"Adding endpoint failed: {e}")


@api.delete("/nodes/name/<node>", summary="Delete node by name")
@api.delete("/nodes/id/<int:id>", summary="Delete node by ID")
@httpauth.login_required
@admin_required
def delete_node(path: NodePath):
    node = path.node
    node_id = path.id
    from janus.api.manager import ServiceManagerException

    try:
        if node:
            return jsonify(cfg.sm.delete_endpoint(name=node))
        else:
            return jsonify(cfg.sm.delete_endpoint(id=node_id))
    except ServiceManagerException as e:
        raise BadRequest(f"Deleting endpoint failed: {e}")
    except Exception as e:
        raise InternalServerError(f"Deleting endpoint failed: {e}")


@api.post("/create", summary="Create one or more new sessions.")
@httpauth.login_required
def create_sessions(body: SessionRequestList):
    """
    Create one or more new sessions.
    """
    (user, group) = get_authinfo(request)
    req = body.root
    req = [r.model_dump() for r in req]

    log.debug(req)
    from janus.api.session_manager import (
        SessionManager,
        InvalidSessionRequestException,
        ResourceNotFoundException,
        SessionManagerException,
    )

    try:
        session_manager = SessionManager()
        current_user = user if user else httpauth.current_user()
        users = user.split(",") if user else []
        session_manager.validate_request(req)
        session_requests = session_manager.parse_requests(user, group, req)
        session_manager.create_networks(session_requests)
        janus_sessionid = session_manager.create_session(
            user, group, session_requests, req, current_user, users
        )
        return jsonify({janus_sessionid: dict(id=janus_sessionid)})
    except InvalidSessionRequestException as e:
        raise BadRequest(f"Creating session failed: {e}")
    except ResourceNotFoundException as e:
        raise NotFound(f"Creating session failed: {e}")
    except SessionManagerException as e:
        raise InternalServerError(f"Creating session failed: {e}")
    except Exception as e:
        raise InternalServerError(f"Creating session failed. Unexpected: {type(e)}:{e}")


@api.put("/start/<int:aid>", summary="Start a container service by id.")
@httpauth.login_required
def start_session_endpoint(path: ActivePath):
    """
    Start a container service by id.
    """
    id = path.aid
    from janus.api.session_manager import (
        SessionManager,
        ResourceNotFoundException,
        SessionManagerException,
    )

    (user, group) = get_authinfo(request)
    try:
        session_manager = SessionManager()
        return jsonify(session_manager.start_session(id, user, group))
    except ResourceNotFoundException as e:
        raise NotFound(f"Creating session failed:{e}")
    except SessionManagerException as e:
        raise InternalServerError(f"Starting session failed:{e}")
    except Exception as e:
        raise InternalServerError(f"Starting session failed:FATAL:{type(e)}:{e}")


@api.put("/stop/<int:aid>", summary="Stop a container service by id.")
@httpauth.login_required
def stop_session_endpoint(path: ActivePath):
    """
    Stop a container service by id.
    """
    id = path.aid
    from janus.api.session_manager import (
        SessionManager,
        ResourceNotFoundException,
        SessionManagerException,
    )

    try:
        session_manager = SessionManager()
        return jsonify(session_manager.stop_session(id))
    except ResourceNotFoundException as e:
        raise NotFound(f"Creating session failed:{e}")
    except SessionManagerException as e:
        raise InternalServerError(f"Stopping session failed:{e}")
    except Exception as e:
        raise InternalServerError(f"Stopping session failed:FATAL:{type(e)}:{e}")


@api.post("/exec", summary="Execute a container command inside an active session.")
@httpauth.login_required
def exec_command(body: ExecRequest):
    """
    Execute a container command inside an active session.
    """
    req = body.model_dump()
    log.debug(req)

    nname = req["node"]
    start = req.get("start", False)
    attach = req.get("attach", True)
    tty = req.get("tty", False)

    dbase = cfg.db
    table = dbase.get_table("nodes")
    node = dbase.get(table, name=nname)
    if not node:
        return jsonify({"error": f"Node not found: {nname}"}), 404

    container = req["container"]
    cmd = req["Cmd"]

    kwargs = {
        "AttachStdin": attach,
        "AttachStdout": attach,
        "AttachStderr": attach,
        "Tty": tty,
        "Cmd": cmd,
    }

    try:
        handler = cfg.sm.get_handler(nname=nname)
        n = Node(**node)
        return jsonify(handler.exec_command(n, container, kwargs, start))
    except Exception as e:
        return jsonify({"error": f"Could not execute command: {e}"}), 500


@api.get("/images", summary="Get images")
@api.get("/images/name/<path:name>", summary="Get a specific image")
@httpauth.login_required
def get_images(path: ImagePath):
    """
    List all images or a specific image.
    """
    name = path.name
    dbase = cfg.db
    table = dbase.get_table("images")
    if name:
        res = dbase.get(table, name=name)
        if not res:
            return {"error": "Not found"}, 404
        return jsonify(res)
    return jsonify(dbase.all(table))


class ProfileQuery(BaseModel):
    refresh: Optional[bool] = False
    reset: Optional[bool] = False


def _handle_get_profiles(resource, query, rname=None):
    resources = [Constants.HOST, Constants.NET, Constants.VOL, Constants.QOS]
    if resource not in resources:
        return {"error": f"Invalid resource path: {resource}"}, 404

    refresh = query.refresh
    reset = query.reset
    (user, group) = get_authinfo(request)

    if refresh:
        try:
            cfg.pm.read_profiles(refresh=True)
        except Exception as e:
            return {"error": str(e)}, 500

    if reset:
        try:
            cfg.pm.read_profiles(reset=True)
        except Exception as e:
            return {"error": str(e)}, 500

    if rname:
        res = cfg.pm.get_profile(resource, rname, user, group, inline=True)
        if not res:
            return {"error": f"Profile not found: {rname}"}, 404
        return jsonify(res.dict())
    else:
        log.debug("Returning all profiles")
        ret = [
            p.dict() for p in cfg.pm.get_profiles(resource, user, group, inline=True)
        ]
        return jsonify(ret if ret else list())


@api.get("/profiles", summary="Get host profiles (default)")
@httpauth.login_required
def get_profiles_default(query: ProfileQuery):
    """
    Get host profiles (defaults to 'host' resource).
    """
    return _handle_get_profiles("host", query)


@api.get("/profiles/<path:resource>", summary="Get profiles for a resource")
@httpauth.login_required
def get_profiles_by_resource(path: ProfileResourcePath, query: ProfileQuery):
    """
    Get all profiles for a specific resource type.
    """
    return _handle_get_profiles(path.resource, query)


@api.get("/profiles/<path:resource>/<path:rname>", summary="Get a specific profile")
@httpauth.login_required
def get_profile_by_name(path: ProfileFullByPath, query: ProfileQuery):
    """
    Get a specific profile by resource type and name.
    """
    return _handle_get_profiles(path.resource, query, rname=path.rname)


@api.post("/profiles/<path:resource>/<path:rname>", summary="Create a new profile")
@httpauth.login_required
def post_profile(path: ProfileFullByPath, body: ProfileRequest):
    """
    Create a new profile.
    """
    resource = path.resource
    rname = path.rname
    resources = [Constants.HOST, Constants.NET, Constants.VOL, Constants.QOS]

    try:
        if not resource or resource not in resources:
            return {"error": f"Invalid resource path: {resource}"}, 404

        configs = body.settings
        res = cfg.pm.get_profile(resource, rname, inline=True)
        if res:
            return {"error": f"Profile {rname} already exists!"}, 400

        if resource == Constants.HOST:
            default = cfg._base_profile.copy()
        elif resource == Constants.VOL:
            default = cfg._base_volumes.copy()
        elif resource == Constants.NET:
            default = cfg._base_networks.copy()
        else:
            default = {}

        default.update((k, configs[k]) for k in default.keys() & configs.keys())
        prof = {"name": rname, "settings": default}
        if resource == Constants.HOST:
            ContainerProfile(**prof)
        elif resource == Constants.VOL:
            VolumeProfile(**prof)
        elif resource == Constants.NET:
            NetworkProfile(**prof)

    except ValidationError as e:
        return str(e), 400
    except Exception as e:
        return str(e), 500

    try:
        tbl = cfg.db.get_table(resource)
        record = {"name": rname, "settings": default}
        res = cfg.db.insert(tbl, record)
        log.info(f"Created {res}")
    except Exception as e:
        return str(e), 500

    return jsonify(cfg.pm.get_profile(resource, rname).dict()), 200


@api.delete("/profiles/<path:resource>/<path:rname>", summary="Remove a profile")
@httpauth.login_required
def delete_profile(path: ProfileFullByPath):
    """
    Remove a profile.
    """
    resource = path.resource
    rname = path.rname
    resources = [Constants.HOST, Constants.NET, Constants.VOL, Constants.QOS]

    if not resource or resource not in resources:
        return {"error": f"Invalid resource path: {resource}"}, 404
    try:
        (user, group) = get_authinfo(request)

        if not rname:
            raise BadRequest("Must specify profile name")

        if rname == "default":
            raise BadRequest("Cannot delete default profile")

        res = cfg.pm.get_profile(resource, rname, user, group, inline=True)
        if not res:
            return {"error": f"Profile not found: {rname}"}, 404

    except Exception as e:
        return str(e), 500

    try:
        profile_tbl = cfg.db.get_table(resource)
        cfg.db.remove(profile_tbl, name=rname)
    except Exception as e:
        return str(e), 500

    return {}, 204


@api.get("/auth/<path:resource>", summary="Get auth info")
@api.get(
    "/auth/res/<path:resource>/id/<int:rid>", summary="Get specific auth info by ID"
)
@api.get(
    "/auth/res/<path:resource>/name/<path:rname>",
    summary="Get specific auth info by name",
)
@httpauth.login_required
def get_auth(path: AuthPath):
    """
    List all auth info or a specific auth info.
    """
    resource = path.resource
    rid = path.rid
    rname = path.rname
    (user, group) = get_authinfo(request)
    dbase = cfg.db
    table = dbase.get_table("auth")
    quser = QueryUser()
    q = quser.query_builder(user, group, {"resource": resource})
    if rid:
        q = quser.query_builder(user, group, {"resource": resource, "id": rid})
        res = dbase.get(table, query=q)
        if not res:
            return {"error": "Not found"}, 404
        return jsonify(res)
    if rname:
        q = quser.query_builder(user, group, {"resource": resource, "name": rname})
        res = dbase.get(table, query=q)
        if not res:
            return {"error": "Not found"}, 404
        return jsonify(res)
    return jsonify(dbase.search(table, query=q))
