"""HTTP contracts for the isolated source preview."""
import http.client
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
import dashboard_preview as preview

class PreviewTest(unittest.TestCase):
    def test_live_source_and_read_only_boundary(self):
        with tempfile.TemporaryDirectory(prefix="veyl-preview-test-") as tmp:
            root=Path(tmp)
            source=Path(__file__).resolve().parents[1]
            for path in [preview.INDEX,*(item[0] for item in preview.ASSETS.values())]:
                dest=root/path
                dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source/path,dest)
            server=ThreadingHTTPServer(("127.0.0.1",0),preview.handler(root,0))
            port=server.server_port
            server.RequestHandlerClass=preview.handler(root,port)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            def request(path,method="GET",host=None):
                c=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
                try:
                    c.request(method,path,headers={"Host":host or f"localhost:{port}"})
                    r=c.getresponse()
                    return r.status,r.read(),dict(r.getheaders())
                finally:
                    c.close()
            try:
                status,html,headers=request("/dashboard")
                self.assertEqual(status,200)
                self.assertIn(b"DEVELOPMENT PREVIEW",html)
                self.assertEqual(headers["Cache-Control"],"no-store")
                self.assertNotIn("Set-Cookie",headers)
                rev=json.loads(request("/preview/revision")[1])["revision"]
                css=root/"src/http/dashboard/style.css"
                css.write_bytes(css.read_bytes()+b"\n/* preview-test */\n")
                self.assertNotEqual(json.loads(request("/preview/revision")[1])["revision"],rev)
                self.assertIn(b"preview-test",request("/dashboard/style.css")[1])
                for section in preview.DIAGNOSTICS:
                    status,raw,_=request("/dashboard/api/diagnostics?section="+section)
                    self.assertEqual(status,200)
                    self.assertIn(section,json.loads(raw)["sections"])
                self.assertEqual(request("/dashboard/api/jobs/cancel","POST")[0],403)
                self.assertEqual(request("/dashboard/api/status",host="example.org")[0],403)
                self.assertEqual(request("/.git/config")[0],404)
                self.assertEqual(request("/dashboard/api/diagnostics?section=unknown")[0],404)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

if __name__=="__main__":
    unittest.main()
