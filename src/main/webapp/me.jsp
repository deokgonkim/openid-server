<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<%@ page contentType="text/html;charset=UTF-8" errorPage="/error.jsp"%>
<%@ page import="net.dgkim.openid.util.UrlUtils" %>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title><%=request.getAttribute("username")%>'s OpenId Identity Page</title>
    <link rel="openid.server" href="<%=UrlUtils.getBaseUrl(request)%>/login">
  </head>
  <body>
<h1><%=request.getAttribute("username")%>'s OpenID Identity Page</h1>
<p>
This is a sample OpenID identity page. It contains a &lt;link&gt; tag with the OpenID server.
</p>
  </body>
</html>