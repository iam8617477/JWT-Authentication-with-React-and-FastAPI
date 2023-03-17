import axios from "axios";

const API_URL = "http://localhost:8000";

const registerAdmin = (username, password) => {
  return axios
    .post(API_URL + "/register-admin", {
      username,
      password,
    },
    { headers: {"Content-Type": "application/x-www-form-urlencoded"} })
    .then((response) => {
      return response.data;
    });
};

const login = (username, password) => {
  return axios
    .post(API_URL + "/token", {
      username,
      password,
    },
    { headers: {"Content-Type": "application/x-www-form-urlencoded"} })
    .then((response) => {
      if (response.data.accessToken) {
        localStorage.setItem("token", JSON.stringify(response.data.accessToken));
      }

      return response.data;
    });
};

const logout = () => {
  localStorage.removeItem("token");
};

const getToken = () => {
  return JSON.parse(localStorage.getItem("token"));
};

const authService = {
  registerAdmin,
  login,
  logout,
  getToken,
};

export default authService;
