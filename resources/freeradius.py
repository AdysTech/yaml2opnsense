"""FreeRADIUS user management for OPNsense via MVC API."""
from core.client import OpnClient


def build_radius_users(cfg):
    """
    Build FreeRADIUS users from `free_radius_users` config.

    Expected format:
      free_radius_users:
        - vlan_name:
            - mac: XX:XX:XX:XX:XX:XX
              description: optional
              password: optional (defaults to MAC)
              enabled: optional (defaults to true)

    VLAN ID is derived from vlans.<vlan_name>.id
    """
    raw = cfg.get("free_radius_users", [])
    vlans = cfg.get("vlans", {})
    users = []

    for item in raw:
        if not isinstance(item, dict) or len(item) != 1:
            continue

        vlan_name, entries = next(iter(item.items()))
        vlan_id = vlans.get(vlan_name, {}).get("id")

        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            mac = entry.get("mac")
            if not mac:
                continue

            user = {
                "enabled": "1" if entry.get("enabled", True) else "0",
                "username": str(mac),
                "password": str(entry.get("password", mac)),
                "passwordencryption": "Cleartext-Password",
                "description": str(entry.get("description", "")),
            }

            if vlan_id is not None:
                user["vlan"] = str(int(vlan_id))

            users.append(user)

    return users


def build_radius_clients(cfg):
    """
    Build FreeRADIUS clients (RADIUS servers, e.g. wireless APs) from `free_radius_clients` config.

    Expected format:
      free_radius_clients:
        my-ap:
          ip: 192.168.20.4
          secret: "shared-radius-secret"
          enabled: optional (defaults to true)
          require_ma: optional (defaults to true)

    The mapping key is used as the client name.
    """
    raw = cfg.get("free_radius_clients", {})
    clients = []

    if not isinstance(raw, dict):
        raise ValueError("free_radius_clients must be a mapping of client name -> settings")

    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"free_radius_clients.{name} must be a mapping")

        ip = entry.get("ip")
        secret = entry.get("secret")
        if not ip or not secret:
            raise ValueError(f"free_radius_clients.{name} requires 'ip' and 'secret'")

        clients.append({
            "enabled": "1" if entry.get("enabled", True) else "0",
            "name": str(name),
            "secret": str(secret),
            "ip": str(ip),
            "require_ma": "1" if entry.get("require_ma", True) else "0",
        })

    return clients


def _get_all_users(client: OpnClient):
    """Fetch all users at once from /api/freeradius/user/get"""
    try:
        data = client.get("/api/freeradius/user/get")
        users = data.get("user", {}).get("users", {}).get("user", {})
        result = []
        if isinstance(users, dict):
            for uuid, user_data in users.items():
                if isinstance(user_data, dict):
                    result.append({"uuid": uuid, **user_data})
        return result
    except Exception:
        return []


def _set_user(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/freeradius/user/setUser/{uuid}", {"user": payload})


def _add_user(client: OpnClient, payload: dict):
    return client.post("/api/freeradius/user/addUser", {"user": payload})


def _get_all_clients(client: OpnClient):
    """Fetch all clients at once from /api/freeradius/client/get"""
    try:
        data = client.get("/api/freeradius/client/get")
        clients = data.get("client", {}).get("clients", {}).get("client", {})
        result = []
        if isinstance(clients, dict):
            for uuid, client_data in clients.items():
                if isinstance(client_data, dict):
                    result.append({"uuid": uuid, **client_data})
        return result
    except Exception as exc:
        # A failed list read would cause duplicate adds below, so fail loudly.
        raise RuntimeError(f"Failed to list FreeRADIUS clients: {exc}") from exc


def _set_client(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/freeradius/client/set_client/{uuid}", {"client": payload})


def _add_client(client: OpnClient, payload: dict):
    return client.post("/api/freeradius/client/add_client/", {"client": payload})


def apply_freeradius(cfg, client: OpnClient):
    """
    Idempotently apply FreeRADIUS users and clients to OPNsense via MVC API.
    - Adds new users / updates existing users when fields differ (username match)
    - Adds new clients (RADIUS servers, e.g. wireless APs) / updates on diff (name match)
    - Does not remove users or clients not in config
    - Triggers service reconfigure if any change
    """
    desired_users = build_radius_users(cfg)
    desired_clients = build_radius_clients(cfg)

    _changed = False

    # Users: add new, update on diff (no removal of users not in config)
    if desired_users:
        existing_users = _get_all_users(client)
        by_username = {str(u.get("username", "")): u for u in existing_users if u.get("username")}

        def equal_enough(current: dict, desired: dict) -> bool:
            return (
                str(current.get("username", "")) == desired.get("username", "")
                and str(current.get("description", "")) == desired.get("description", "")
                and str(current.get("vlan", "")) == str(desired.get("vlan", ""))
            )

        for user in desired_users:
            uname = user["username"]
            if uname in by_username:
                current = by_username[uname]
                if not equal_enough(current, user):
                    _set_user(client, current["uuid"], user)
                    _changed = True
            else:
                _add_user(client, user)
                _changed = True

    # Clients (RADIUS servers): add new, update on diff (no removal)
    if desired_clients:
        existing_clients = _get_all_clients(client)
        by_name = {str(c.get("name", "")): c for c in existing_clients if c.get("name")}

        for rad_client in desired_clients:
            if rad_client["name"] in by_name:
                current = by_name[rad_client["name"]]
                diff_fields = ("ip", "secret", "enabled", "require_ma")
                if any(str(current.get(f, "")) != str(rad_client.get(f, "")) for f in diff_fields):
                    _set_client(client, current["uuid"], rad_client)
                    _changed = True
            else:
                _add_client(client, rad_client)
                _changed = True

    if _changed:
        client.post("/api/freeradius/service/reconfigure")
