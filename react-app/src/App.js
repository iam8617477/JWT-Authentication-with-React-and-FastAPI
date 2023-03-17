import { useState, useEffect } from "react";
import { Routes, Route, Link } from "react-router-dom";
import AuthService from "./services/auth.service";
import Login from "./components/Login";
import Signup from "./components/Signup";
import User from "./components/User";
import Private from "./components/Private";


function App() {
  const [token, setToken] = useState(undefined);

  useEffect(() => {
    const token = AuthService.getToken();

    if (token) {
      setToken(token);
    }
  }, []);

  const logOut = () => {
    AuthService.logout();
  };

  return (
    <div>
            <nav>
        {token ? (
          <div>
            <li>
              <Link to={"/user"}>
                User
              </Link>
            </li>
            <li>
              <Link to={"/private"}>
                Private
              </Link>
            </li>
            <li>
              <a href="/login" onClick={logOut}>
                Logout
              </a>
            </li>
          </div>
        ) : (
          <div>
            <li>
              <Link to={"/login"}>
                Login
              </Link>
            </li>

            <li>
              <Link to={"/signup"}>
                Sign up
              </Link>
            </li>
          </div>
        )}
      </nav>
      <div>
        <Routes>
          <Route path="/user" element={<User />} />
          <Route path="/private" element={<Private />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
        </Routes>
      </div>
    </div>
  );
}

export default App;
