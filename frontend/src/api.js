import axios from "axios";

// Fetch API base URL from backend
export const getApiBaseUrl = async () => {
  try {
    const response = await axios.get("http://localhost:4000/config");
    return response.data.apiBaseUrl;
  } catch (error) {
    console.error("Error fetching API base URL:", error);
    return "http://localhost:4000"; // Default fallback
  }
};

// Login request
export const loginUser = async (role, password) => {
  const apiBaseUrl = await getApiBaseUrl();
  return axios.post(`${apiBaseUrl}/login`, { role, password });
};
