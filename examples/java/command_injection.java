import java.io.IOException;
import java.sql.Statement;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// CWE-78 / CWE-89: request input reaching exec and executeQuery.
public class Cmd extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);

        String name = request.getParameter("name");
        try {
            Statement st = null;
            st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        } catch (Exception e) {
            response.sendError(500, e.getMessage());
        }
    }
}
