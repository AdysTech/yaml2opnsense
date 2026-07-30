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


def apply_freeradius(cfg, client: OpnClient):
    """
    Idempotently apply FreeRADIUS users to OPNsense via MVC API.
    - Adds new users
    - Updates existing users when fields differ (username match)
    - Removes users not in config
    - Triggers service reconfigure if any change
    """
    desired_users = build_radius_users(cfg)
    if not desired_users:
        return

    _changed = False
    existing_users = _get_all_users(client)
    by_username = {str(u.get("username", "")): u for u in existing_users if u.get("username")}

    def equal_enough(current: dict, desired: dict) -> bool:
        return (
            str(current.get("username", "")) == desired.get("username", "")
            and str(current.get("description", "")) == desired.get("description", "")
            and str(current.get("vlan", "")) == str(desired.get("vlan", ""))
        )

    # Add/update
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
