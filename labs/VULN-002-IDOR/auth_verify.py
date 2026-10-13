"""Real HTTP authentication and shared-cookie-jar regression, no article attack."""
import http.cookiejar
import uuid
import db
import runtime as rt


def verify():
    run=uuid.uuid4().hex
    passwords=["Alice-"+uuid.uuid4().hex,"Bob-"+uuid.uuid4().hex]
    hashes=[rt.password_hash(value) for value in passwords]
    original={variant:db.snapshot(variant) for variant in rt.BASES}
    fixtures={}
    try:
        for variant in rt.BASES: fixtures[variant]=db.prepare(variant,run,hashes)
        seeded={variant:db.snapshot(variant) for variant in rt.BASES}
        shared=http.cookiejar.CookieJar()
        clients={variant:rt.Client(variant,shared) for variant in rt.BASES}
        for variant,client in clients.items():
            client.csrf()
            before={cookie.name:cookie.value for cookie in shared}
            client.request("POST",rt.PREFIX+"/auth/login",403,{"username":fixtures[variant]["names"][0],"password":passwords[0]},form=True,csrf=False)
            old=client.token
            client.login(fixtures[variant]["names"][0],passwords[0])
            cookie_name="JSESSIONID" if variant=="vulnerable" else "VULN002SECSESSION"
            after={cookie.name:cookie.value for cookie in shared}
            assert cookie_name in after and before[cookie_name]!=after[cookie_name]
            current=client.token; client.token=old
            client.request("POST",rt.PREFIX+"/auth/logout",403)
            client.token=current
            assert client.request("GET",rt.PREFIX+"/auth/me",200)["id"]==fixtures[variant]["users"][0]
        assert {cookie.name for cookie in shared}=={"JSESSIONID","VULN002SECSESSION"}
        # Cookie policy attaches both names to both ports; server cookie names choose distinct sessions.
        for variant in rt.BASES:
            request=__import__("urllib.request",fromlist=["Request"]).Request(rt.BASES[variant]+rt.PREFIX+"/auth/me")
            shared.add_cookie_header(request)
            assert "JSESSIONID=" in request.get_header("Cookie") and "VULN002SECSESSION=" in request.get_header("Cookie")
            assert clients[variant].request("GET",rt.PREFIX+"/auth/me",200)["id"]==fixtures[variant]["users"][0]
        clients["vulnerable"].request("GET","/api/users/me",401)
        clients["vulnerable"].request("GET","/api/labs/vuln001/info",401)
        # Send only another app's cookie: cannot authenticate this application.
        for variant,other_name in [("secure","JSESSIONID"),("vulnerable","VULN002SECSESSION")]:
            wrong=http.cookiejar.CookieJar()
            for cookie in shared:
                if cookie.name==other_name: wrong.set_cookie(cookie)
            rt.Client(variant,wrong).request("GET",rt.PREFIX+"/auth/me",401)
        for variant,client in clients.items():
            client.request("POST",rt.PREFIX+"/auth/logout",200)
            client.request("GET",rt.PREFIX+"/auth/me",401)
            assert db.snapshot(variant)==seeded[variant]
        print("Stage B real HTTP PASS: shared jar sends both cookie names to both ports; sessions remain separate; CSRF/fixation/context isolation verified; exit code 0",flush=True)
    finally:
        for variant in rt.BASES: db.cleanup(variant,run)
        for variant in rt.BASES: assert db.snapshot(variant)==original[variant]


if __name__=="__main__":
    with rt.Servers(label="stage-b"): verify()
