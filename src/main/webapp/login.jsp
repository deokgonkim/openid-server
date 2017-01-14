<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<%--
  - request.getAttribute("errorMsg")
  - request.getAttribute("query")
  - request.getAttribute("realm")
  --%>
<%@ page contentType="text/html;charset=UTF-8" errorPage="/error.jsp"%>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title>login</title>
    <style type="text/css">
        .error {
            font-weight: bold;
            color: red;
        }
    </style>
  </head>
  <body>
    <div class="error"><%=request.getAttribute("errorMsg")%></div>
    <form action="http://<%=request.getServerName() %><%=request.getContextPath() %>/loginform" method="post">
    <input type="hidden" name="query" value="<%=request.getAttribute("query")%>"/>
    <input type="hidden" name="openid.realm" value="<%=request.getAttribute("realm")%>"/>

    <p>
        Allow access to: <a href="<%=request.getAttribute("realm")%>" target="_blank"><%=request.getAttribute("realm")%></a>?
    </p>
    <table border="0">
        <tr>
            <td>Username:</td>
            <td><input type="text" name="username"/></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type="password" name="password"/></td>
        </tr>
        <tr>
            <td>Create New User?</td>
            <td><input type="checkbox" name="newuser"/></td>
        </tr>
         <tr>
            <td>Remember Me?</td>
            <td><input type="checkbox" name="rememberMe"/></td>
        </tr>
        <tr>
            <td>&nbsp;</td>
            <td><input type="submit" value="Submit"/></td>
        </tr>
    </table>
</form>
<p>
    Logged in as: <%=session.getAttribute("user")%>
</p>
  </body>
</html>