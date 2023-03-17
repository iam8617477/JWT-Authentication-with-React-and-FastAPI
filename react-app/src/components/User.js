import React, { useState, useEffect } from "react";
import Resurce from "../services/resurce.service";
import AuthService from "../services/auth.service";
import { useNavigate } from "react-router-dom";

const User = () => {
  const [user, setUser] = useState([]);

  const navigate = useNavigate();

  useEffect(() => {
    Resurce.getCurrentUser().then(
      (response) => {
        setUser(response.data);
      },
      (error) => {
        console.log("User page", error.response);
        // Invalid token
        if (error.response && error.response.status === 403) {
          AuthService.logout();
          navigate("/login");
          window.location.reload();
        }
      }
    );
  }, []);

  return (
    <div>
      <h3>
          <div>{user.username}</div>
      </h3>
    </div>
  );
};

export default User;
