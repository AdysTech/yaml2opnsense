from core.client import OpnClient


def build_haproxy_config(cfg):
    """
    Build HAProxy configuration from YAML config.
    Returns dict with servers, backends, and frontends.
    """
    haproxy_cfg = cfg.get("haproxy", {})
    
    if not haproxy_cfg.get("enabled", False):
        return None
    
    # Build hostname → IP map from static_leases
    hostname_ip_map = {}
    for vlan in cfg.get("vlans", {}).values():
        for lease in vlan.get("static_leases", {}).values():
            hostname = lease.get("hostname")
            ip = vlan.get("gateway") if lease.get("ip") == "gateway" else lease.get("ip")
            if hostname and ip:
                hostname_ip_map[hostname] = ip
    
    config = {
        "servers": [],
        "healthchecks": [],
        "actions": [],
        "backends": [],
        "frontends": [],
    }
    
    # Build servers from backends
    for backend_name, backend_def in haproxy_cfg.get("backends", {}).items():
        # Get port from backend service definition (common for all servers in this backend)
        backend_port = str(backend_def.get("service", {}).get("port", "80"))
        
        for server in backend_def.get("servers", []):
            server_name = server.get("name", "")
            address = server.get("address", "")
            
            # Resolve hostname to IP if address is just a hostname or hostname:port
            if ":" in address:
                # Address contains explicit port (e.g., "192.168.1.1:8080")
                host_part, port = address.rsplit(":", 1)
            else:
                # No port in address, use backend service port
                host_part = address
                port = backend_port
            
            # If host_part is a hostname (not an IP), resolve it
            if host_part and "." not in host_part:
                # It's likely a hostname, try to resolve from static_leases
                resolved_ip = hostname_ip_map.get(server_name)
                if resolved_ip:
                    ip = resolved_ip
                else:
                    # Fall back to using address as-is (might be IP)
                    ip = host_part
            elif host_part=='':
                resolved_ip = hostname_ip_map.get(server_name)
                if resolved_ip:
                    ip = resolved_ip
                else:
                    # Fall back to using address as-is (might be IP)
                    ip = host_part
            else:
                ip = host_part  


            # Get check_interval from server or backend health_check
            check_interval = server.get("check_interval")
            if not check_interval:
                health_check = backend_def.get("health_check", {})
                check_interval = health_check.get("check_interval", "5s")
            
            
            config["servers"].append({
                "name": f"{server_name}_{backend_name}",
                "address": ip,
                "port": port,
                "checkport": server.get("check_port", port),
                "check": "1" if server.get("check", True) else "0",
                "checkinterval": check_interval,
                "enabled": "1",
                "description": f"Server {server_name} for {backend_name}",
            })
    
    # Build health checks from backends
    for backend_name, backend_def in haproxy_cfg.get("backends", {}).items():
        health_check = backend_def.get("health_check", {})
        if health_check:
            mode = backend_def.get("mode", "http")
            hc_config = {
                "name": f"{backend_name}_healthcheck",
                "description": f"Health check for {backend_name}",
                "type": "http" if mode == "http" else "tcp",
            }
            
            if mode == "http":
                hc_config["http_method"] = health_check.get("method", "head").lower()
                hc_config["http_uri"] = health_check.get("uri", "/")
            
            if "port" in health_check:
                hc_config["checkport"] = str(health_check["port"])
            
            config["healthchecks"].append(hc_config)
    
    # Build actions from backends
    for backend_name, backend_def in haproxy_cfg.get("backends", {}).items():
        http_request = backend_def.get("http_request", [])
        for idx, action_def in enumerate(http_request):
            action_type = action_def.get("action", "set-header")
            action_name = action_def.get("name", "")
            action_value = action_def.get("value", "")
            
            # Build action name that's unique per backend
            action_full_name = f"{backend_name}_{action_type}_{action_name}_{idx}"
            
            # Build action payload based on OPNsense structure
            action_payload = {
                "name": action_full_name,
                "description": f"{action_type} {action_name} for {backend_name}",
                "type": f"http-request_{action_type}",
                "backend_name": backend_name,  # Track which backend this belongs to
            }
            
            # Add type-specific fields
            if action_type == "set-header":
                action_payload["http_request_set_header_name"] = action_name
                action_payload["http_request_set_header_content"] = action_value
            elif action_type == "add-header":
                action_payload["http_request_add_header_name"] = action_name
                action_payload["http_request_add_header_content"] = action_value
            
            config["actions"].append(action_payload)
    
    # Build backends
    for backend_name, backend_def in haproxy_cfg.get("backends", {}).items():
        mode = backend_def.get("mode", "http")
        balance = backend_def.get("balance", "roundrobin")
        
        # Get linked servers - use unique names matching what we created
        linked_servers = []
        for server in backend_def.get("servers", []):
            linked_servers.append( f"{server.get("name", "")}_{backend_name}")
        
        backend = {
            "name": backend_name,
            "mode": mode,
            "balance": balance,
            "enabled": "1",
            "description": f"Backend pool for {backend_name}",
            "linkedServers": ",".join(linked_servers),  # Will be replaced with UUIDs
            "linkedActions": backend_name,  # Placeholder, will be replaced with UUIDs
        }
        
        # Link to health check monitor (will be replaced with UUID)
        if backend_def.get("health_check"):
            backend["healthCheck"] = f"{backend_name}_healthcheck"
        
        # Options
        options = backend_def.get("options", [])
        if "forwardfor" in options:
            backend["forwardfor"] = "1"
        if "http-server-close" in options:
            backend["httpClose"] = "1"
        
        # Timeout
        timeout_tunnel = backend_def.get("timeout_tunnel")
        if timeout_tunnel:
            backend["tuning_timeoutTunnel"] = str(timeout_tunnel)
        
        config["backends"].append(backend)
    
    # Build frontends
    bind_address = haproxy_cfg.get("bind_address", "")
    
    for frontend_name, frontend_def in haproxy_cfg.get("frontends", {}).items():
        bind_port = frontend_def.get("bind_port", "")
        mode = frontend_def.get("mode", "http")
        default_backend = frontend_def.get("default_backend", "")
        
        frontend = {
            "name": frontend_name,
            "bind": f"{bind_address}:{bind_port}",
            "mode": mode,
            "defaultBackend": default_backend,  # Will be replaced with UUID
            "enabled": "1",
            "description": f"Frontend listener on port {bind_port}",
        }
        
        # SSL configuration
        if frontend_def.get("ssl", False):
            frontend["ssl_enabled"] = "1"
            ssl_cert_name = frontend_def.get("ssl_cert")
            if ssl_cert_name:
                # Certificate UUIDs will be looked up - set both fields to same cert name
                frontend["ssl_certificates"] = ssl_cert_name
                frontend["ssl_default_certificate"] = ssl_cert_name
        
        # Stats
        if frontend_def.get("stats_enabled", False):
            stats_cfg = haproxy_cfg.get("stats", {})
            frontend["stats_enabled"] = "1"
            frontend["stats_uri"] = stats_cfg.get("uri", "/haproxy_stats")
            frontend["stats_refresh"] = stats_cfg.get("refresh", "10s")
        
        config["frontends"].append(frontend)
    
    return config


def _search_servers(client: OpnClient):
    try:
        data = client.get("/api/haproxy/settings/searchServers")
        return data.get("rows", [])
    except Exception:
        return []


def _add_server(client: OpnClient, payload: dict):
    return client.post("/api/haproxy/settings/addServer", {"server": payload})


def _set_server(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/haproxy/settings/setServer/{uuid}", {"server": payload})


def _search_healthchecks(client: OpnClient):
    try:
        data = client.get("/api/haproxy/settings/searchHealthchecks")
        return data.get("rows", [])
    except Exception:
        return []


def _add_healthcheck(client: OpnClient, payload: dict):
    return client.post("/api/haproxy/settings/addHealthcheck", {"healthcheck": payload})


def _set_healthcheck(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/haproxy/settings/setHealthcheck/{uuid}", {"healthcheck": payload})


def _search_actions(client: OpnClient):
    try:
        data = client.get("/api/haproxy/settings/searchActions")
        return data.get("rows", [])
    except Exception:
        return []


def _add_action(client: OpnClient, payload: dict):
    return client.post("/api/haproxy/settings/addAction", {"action": payload})


def _set_action(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/haproxy/settings/setAction/{uuid}", {"action": payload})


def _search_backends(client: OpnClient):
    try:
        data = client.get("/api/haproxy/settings/searchBackends")
        return data.get("rows", [])
    except Exception:
        return []


def _add_backend(client: OpnClient, payload: dict):
    return client.post("/api/haproxy/settings/addBackend", {"backend": payload})


def _set_backend(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/haproxy/settings/setBackend/{uuid}", {"backend": payload})


def _search_frontends(client: OpnClient):
    try:
        data = client.get("/api/haproxy/settings/searchFrontends")
        return data.get("rows", [])
    except Exception:
        return []


def _get_frontend_options(client: OpnClient):
    """Get frontend options including available certificates."""
    try:
        data = client.get("/api/haproxy/settings/get_frontend")
        return data
    except Exception:
        return {}


def _add_frontend(client: OpnClient, payload: dict):
    return client.post("/api/haproxy/settings/addFrontend", {"frontend": payload})


def _set_frontend(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/haproxy/settings/setFrontend/{uuid}", {"frontend": payload})


def _sync_servers(haproxy_config, client: OpnClient):
    """
    Sync HAProxy servers. Returns (changed, server_uuid_map).
    """
    changed = False
    existing_servers = _search_servers(client)
    # Index by (address, port) for reliable matching
    server_index = {}
    for s in existing_servers:
        addr = s.get("address", "")
        port = s.get("port", "")
        if addr and port:
            server_index[(addr, port)] = s
    
    server_uuid_map = {}
    
    for server in haproxy_config["servers"]:
        name = server["name"]
        addr = server["address"]
        port = server["port"]
        key = (addr, port)
        
        if key in server_index:
            # Update existing server matched by IP:port
            current = server_index[key]
            uuid = current.get("uuid")
            server_uuid_map[name] = uuid
            
            if (
                str(current.get("checkport")) != str(server.get("checkport")) or
                str(current.get("check")) != str(server.get("check", "1")) or
                str(current.get("checkinterval")) != str(server.get("checkinterval")) or
                str(current.get("enabled")) != str(server.get("enabled", "1"))
            ):
                _set_server(client, uuid, server)
                changed = True  
        else:
            # Add new
            result = _add_server(client, server)
            if result and result.get("uuid"):
                server_uuid_map[name] = result["uuid"]
            changed = True
    
    # Refresh server list to get all UUIDs
    if changed:
        existing_servers = _search_servers(client)
        # Rebuild map by name for backend linking
        for srv in existing_servers:
            # Try to match by (address, port) to find our servers
            addr = srv.get("address", "")
            port = srv.get("port", "")
            for server in haproxy_config["servers"]:
                if server["address"] == addr and server["port"] == port:
                    server_uuid_map[server["name"]] = srv.get("uuid")
                    break
    
    return changed, server_uuid_map


def _sync_healthchecks(haproxy_config, client: OpnClient):
    """
    Sync HAProxy health check monitors. Returns (changed, healthcheck_uuid_map).
    """
    changed = False
    existing_healthchecks = _search_healthchecks(client)
    hc_index = {hc.get("name"): hc for hc in existing_healthchecks}
    healthcheck_uuid_map = {}
    
    for hc in haproxy_config["healthchecks"]:
        name = hc["name"]
        
        if name in hc_index:
            # Update existing
            current = hc_index[name]
            uuid = current.get("uuid")
            healthcheck_uuid_map[name] = uuid
            
            # Check if key fields changed
            needs_update = False
            if str(current.get("type")) != str(hc.get("type")):
                needs_update = True
            elif hc.get("type") == "http":
                if (str(current.get("http_method")) != str(hc.get("http_method", "")) or
                    str(current.get("http_uri")) != str(hc.get("http_uri", ""))):
                    needs_update = True
            
            if needs_update:
                _set_healthcheck(client, uuid, hc)
                changed = True
        else:
            # Add new
            result = _add_healthcheck(client, hc)
            if result and result.get("uuid"):
                healthcheck_uuid_map[name] = result["uuid"]
            changed = True
    
    # Refresh list if changed
    if changed:
        existing_healthchecks = _search_healthchecks(client)
        hc_index = {hc.get("name"): hc for hc in existing_healthchecks}
        for name in hc_index:
            if name in [h["name"] for h in haproxy_config["healthchecks"]]:
                healthcheck_uuid_map[name] = hc_index[name].get("uuid")
    
    return changed, healthcheck_uuid_map


def _sync_actions(haproxy_config, client: OpnClient):
    """
    Sync HAProxy actions (http-request directives). Returns (changed, action_uuid_map_by_backend).
    action_uuid_map_by_backend is a dict: backend_name → list of action UUIDs
    """
    changed = False
    existing_actions = _search_actions(client)
    action_index = {a.get("name"): a for a in existing_actions}
    action_uuid_map_by_backend = {}
    
    for action in haproxy_config["actions"]:
        name = action["name"]
        backend_name = action.get("backend_name")  # Get backend name
        
        if backend_name not in action_uuid_map_by_backend:
            action_uuid_map_by_backend[backend_name] = []
        
        # Build API payload without backend_name helper field
        api_payload = {k: v for k, v in action.items() if k != "backend_name"}
        
        if name in action_index:
            # Update existing
            current = action_index[name]
            uuid = current.get("uuid")
            action_uuid_map_by_backend[backend_name].append(uuid)
            
            # Check if key fields changed
            needs_update = (
                str(current.get("type")) != str(action.get("type")) or
                str(current.get("http_request_set_header_name", "")) != str(action.get("http_request_set_header_name", "")) or
                str(current.get("http_request_set_header_content", "")) != str(action.get("http_request_set_header_content", "")) or
                str(current.get("http_request_add_header_name", "")) != str(action.get("http_request_add_header_name", "")) or
                str(current.get("http_request_add_header_content", "")) != str(action.get("http_request_add_header_content", ""))
            )
            
            if needs_update:
                _set_action(client, uuid, api_payload)
                changed = True
        else:
            # Add new
            result = _add_action(client, api_payload)
            if result and result.get("uuid"):
                action_uuid_map_by_backend[backend_name].append(result["uuid"])
            changed = True
    
    # Refresh list if changed
    if changed:
        existing_actions = _search_actions(client)
        action_index = {a.get("name"): a for a in existing_actions}
        # Rebuild map
        action_uuid_map_by_backend = {}
        for action in haproxy_config["actions"]:
            backend_name = action.get("backend_name")
            name = action["name"]
            if backend_name not in action_uuid_map_by_backend:
                action_uuid_map_by_backend[backend_name] = []
            if name in action_index:
                action_uuid_map_by_backend[backend_name].append(action_index[name].get("uuid"))
    
    return changed, action_uuid_map_by_backend


def _sync_backends(haproxy_config, client: OpnClient, server_uuid_map, healthcheck_uuid_map, action_uuid_map_by_backend):
    """
    Sync HAProxy backends. Returns (changed, backend_uuid_map).
    """
    changed = False
    existing_backends = _search_backends(client)
    backend_index = {b.get("name"): b for b in existing_backends}
    backend_uuid_map = {}
    
    for backend in haproxy_config["backends"]:
        name = backend["name"]
        
        # Replace server names with UUIDs
        linked_servers = backend.get("linkedServers", "").split(",")
        linked_uuids = [server_uuid_map.get(srv) for srv in linked_servers if srv in server_uuid_map]
        backend["linkedServers"] = ",".join(filter(None, linked_uuids))
        
        # Replace health check name with UUID
        hc_name = backend.get("healthCheck", "")
        if hc_name and hc_name in healthcheck_uuid_map:
            backend["healthCheck"] = healthcheck_uuid_map[hc_name]
        
        # Replace linkedActions placeholder with actual UUIDs
        linked_actions_placeholder = backend.get("linkedActions", "")
        if linked_actions_placeholder in action_uuid_map_by_backend:
            action_uuids = action_uuid_map_by_backend[linked_actions_placeholder]
            backend["linkedActions"] = ",".join(action_uuids)
        else:
            backend["linkedActions"] = ""  # No actions for this backend
        
        if name in backend_index:
            # Update existing
            current = backend_index[name]
            uuid = current.get("uuid")
            backend_uuid_map[name] = uuid
            
            if (
                str(current.get("mode")) != str(backend.get("mode")) or
                str(current.get("balance")) != str(backend.get("balance")) or
                str(current.get("linkedServers")) != backend.get("linkedServers", "")
            ):
                _set_backend(client, uuid, backend)
                changed = True
        else:
            # Add new
            result = _add_backend(client, backend)
            if result and result.get("uuid"):
                backend_uuid_map[name] = result["uuid"]
            changed = True
    
    # Refresh backend list
    if changed:
        existing_backends = _search_backends(client)
        backend_index = {b.get("name"): b for b in existing_backends}
        for name, be in backend_index.items():
            backend_uuid_map[name] = be.get("uuid")
    
    return changed, backend_uuid_map


def _sync_frontends(haproxy_config, client: OpnClient, backend_uuid_map):
    """
    Sync HAProxy frontends. Returns changed flag.
    """
    changed = False
    existing_frontends = _search_frontends(client)
    frontend_index = {f.get("name"): f for f in existing_frontends}
    
    # Build certificate name → UUID map from frontend options
    options = _get_frontend_options(client)
    cert_map = {}
    ssl_certs = options.get("frontend", {}).get("ssl_default_certificate", {})
    for cert_uuid, cert_data in ssl_certs.items():
        if cert_uuid and cert_uuid != "":  # Skip empty key
            cert_value = cert_data.get("value", "")
            if cert_value:
                # Store both full name and base name for matching
                cert_map[cert_value] = cert_uuid
                # Extract base name (e.g., "*.adystech.com" from "*.adystech.com (ACME Client)")
                base_name = cert_value.split(" (")[0] if " (" in cert_value else cert_value
                cert_map[base_name] = cert_uuid
    
    for frontend in haproxy_config["frontends"]:
        name = frontend["name"]
        
        # Replace backend name with UUID
        default_backend_name = frontend.get("defaultBackend", "")
        if default_backend_name in backend_uuid_map:
            frontend["defaultBackend"] = backend_uuid_map[default_backend_name]
        
        # Replace certificate name with UUID (works with partial match now)
        ssl_cert_name = frontend.get("ssl_default_certificate", "")
        if ssl_cert_name and ssl_cert_name in cert_map:
            cert_uuid = cert_map[ssl_cert_name]
            frontend["ssl_certificates"] = cert_uuid
            frontend["ssl_default_certificate"] = cert_uuid
        elif ssl_cert_name:
            # Certificate not found
            print(f"Warning: Certificate '{ssl_cert_name}' not found, SSL will be disabled for frontend '{name}'")
            print(f"Available certificates: {list(set(cert_map.keys()))}")
            frontend.pop("ssl_certificates", None)
            frontend.pop("ssl_default_certificate", None)
            frontend.pop("ssl_enabled", None)
        
        if name in frontend_index:
            # Update existing
            current = frontend_index[name]
            uuid = current.get("uuid")
            
            if (
                str(current.get("bind")) != str(frontend.get("bind")) or
                str(current.get("mode")) != str(frontend.get("mode")) or
                str(current.get("ssl_default_certificate")) != frontend.get("ssl_default_certificate", "") or
                str(current.get("ssl_certificates")) != frontend.get("ssl_certificates", "") or
                str(current.get("defaultBackend")) != frontend.get("defaultBackend", "")

            ):
                _set_frontend(client, uuid, frontend)
                changed = True
        else:
            # Add new
            _add_frontend(client, frontend)
            changed = True
    
    return changed


def apply_haproxy(cfg, client: OpnClient):
    """
    Apply HAProxy configuration to OPNsense idempotently.
    """
    haproxy_config = build_haproxy_config(cfg)
    
    if not haproxy_config:
        return  # HAProxy not enabled
    
    # Sync configuration in dependency order: servers → healthchecks → actions → backends → frontends
    servers_changed, server_uuid_map = _sync_servers(haproxy_config, client)
    healthchecks_changed, healthcheck_uuid_map = _sync_healthchecks(haproxy_config, client)
    actions_changed, action_uuid_map_by_backend = _sync_actions(haproxy_config, client)
    backends_changed, backend_uuid_map = _sync_backends(haproxy_config, client, server_uuid_map, healthcheck_uuid_map, action_uuid_map_by_backend)
    frontends_changed = _sync_frontends(haproxy_config, client, backend_uuid_map)
    
    # Reconfigure if anything changed
    if servers_changed or healthchecks_changed or actions_changed or backends_changed or frontends_changed:
        # Test configuration before applying
        test_result = client.post("/api/haproxy/service/configtest")
        result = test_result.get("result", "").strip()
        # Empty result or whitespace means success; error messages will be non-empty
        if result and result.lower() not in ["ok", ""]:
            raise Exception(f"HAProxy configuration test failed: {result}")
        
        # Configuration is valid, apply it
        client.post("/api/haproxy/service/reconfigure")
