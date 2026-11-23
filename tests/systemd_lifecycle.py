"""Offline service lifecycle in a private session bus and delegated transient cgroup."""

import hashlib,http.client,json,os,pathlib,socket,subprocess,sys,time
base=pathlib.Path(sys.argv[1])
gateway=pathlib.Path(sys.argv[2])
assert os.environ["HOME"]==str(base/"home")
assert os.environ["XDG_RUNTIME_DIR"]==str(base/"run")
assert os.environ["DBUS_SESSION_BUS_ADDRESS"].startswith("unix:path=/tmp/")
assert os.environ["SYSTEMD_UNIT_PATH"].split(":")==[str(base/"units"),str(base/"home/.config/systemd/user")]
(base/"workspace").mkdir(mode=0o700)
(base/"audit").mkdir(mode=0o700)
(base/"jobs").mkdir(mode=0o700)
audit=base/"audit/main.jsonl"
audit.touch(mode=0o600)
config=base/"private.json"
bearer="a3"*32
config.write_text(json.dumps({"policy_version":2,"audit_log":str(audit),
    "job_state_dir":str(base/"jobs"),
    "job_profiles":{"sleep":{"executable":"/usr/bin/sleep","args":["9"],"timeout_seconds":12,"max_output_bytes":4096}},
    "clients":[{"id":"service-probe","root":str(base/"workspace"),"tools":["job_start","job_status","job_cancel"],
    "token_sha256":hashlib.sha256(bearer.encode()).hexdigest(),"expires_at_unix_seconds":int(time.time())+180}]}))
config.chmod(0o600)
with socket.socket() as bound:
    bound.bind(("127.0.0.1",0))
    port=bound.getsockname()[1]
manager_log=(base/"nested-manager.log").open("wb")
command=["/usr/lib/systemd/systemd","--user","--unit=veyl-test.target"]
manager=subprocess.Popen(command,stdout=manager_log,stderr=manager_log)
try:
    for _ in range(40):
        if manager.poll() is not None:
            raise RuntimeError((base/"nested-manager.log").read_text())
        probe=subprocess.run(["systemctl","--user","show","--property=SystemState"],capture_output=True,text=True,timeout=1)
        if probe.returncode==0:
            break
        time.sleep(.15)
    else:
        raise RuntimeError("Isolated manager unavailable: "+(base/"nested-manager.log").read_text())
    print("Private user manager is available",flush=True)
    def action(*args):
        command=[gateway,"service",*args,"--config",config,"--listen",f"127.0.0.1:{port}"]
        r=subprocess.run(command,capture_output=True,text=True,timeout=30)
        if r.returncode!=0:
            raise RuntimeError(f"{args}: {r.stderr}\n{(base/'nested-manager.log').read_text()}")
        print(args[0],r.stdout.strip(),flush=True)
        return r.stdout
    def rpc(method,params,session=None):
        conn=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
        try:
            packet={"jsonrpc":"2.0","id":1,"method":method,"params":params}
            headers={"Authorization":"Bearer "+bearer,"Content-Type":"application/json"}
            if session:
                headers["Mcp-Session-Id"]=session
                if method=="notifications/initialized":
                    packet.pop("id")
            conn.request("POST","/mcp",json.dumps(packet),headers)
            response=conn.getresponse()
            payload=response.read()
            assert response.status in (200,202),(response.status,payload)
            return response.headers.get("Mcp-Session-Id"),json.loads(payload) if payload else None
        finally:
            conn.close()
    def connect():
        for attempt in range(40):
            try:
                session,_=rpc("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"service-fixture","version":"1"}})
                rpc("notifications/initialized",{},session)
                return session
            except OSError:
                time.sleep(.1)
        raise RuntimeError("Service did not start listening")
    def tool(name,args,session):
        _,result=rpc("tools/call",{"name":name,"arguments":args},session)
        assert not result["result"].get("isError"),result
        return json.loads(result["result"]["content"][0]["text"])
    def main_pid():
        return int(subprocess.check_output(["systemctl","--user","show","--property=MainPID","--value","mcp-gateway.service"],timeout=4))
    action("install","--confirm")
    assert "UnitFileState=enabled" in action("enable","--confirm")
    assert "ActiveState=active" in action("start","--confirm")
    before=main_pid()
    assert before>0
    session=connect()
    job=tool("job_start",{"profile":"sleep"},session)["job_id"]
    assert "ActiveState=active" in action("restart","--confirm")
    assert main_pid() not in (0,before)
    session=connect()
    status=tool("job_status",{"job_id":job},session)
    assert status["job_id"]==job
    ended=tool("job_cancel",{"job_id":job},session)
    assert ended["state"]=="canceled"
    print("Authenticated service PID restarted and retained the original cancellable job receipt.")
    assert "ActiveState=inactive" in action("stop","--confirm")
    assert "UnitFileState=disabled" in action("disable","--confirm")
    action("uninstall","--confirm")
    assert not (base/"home"/".config/systemd/user/mcp-gateway.service").exists()
    assert config.exists() and audit.exists()
finally:
    if manager.poll() is None:
        manager.terminate()
        try: manager.wait(timeout=3)
        except subprocess.TimeoutExpired:
            manager.kill();manager.wait(timeout=2)
    manager_log.close()
