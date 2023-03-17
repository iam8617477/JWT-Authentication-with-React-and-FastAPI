import axios from "axios";
import authHeader from "./auth-header";

const API_URL = "http://localhost:8000";

const getCurrentUser = () => {
  return axios.get(API_URL + "/users/me/", { headers: authHeader() });
};

const getPrivateResurce = () => {
  return axios.get(API_URL + "/only-admin/", { headers: authHeader() });
};

const getService = {
  getCurrentUser,
  getPrivateResurce,
};

export default getService;
