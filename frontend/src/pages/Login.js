import React, { useState, useEffect } from "react";
import { loginUser } from "../api"; // Use API helper
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const [role, setRole] = useState(""); // Role or therapist name
  const [password, setPassword] = useState(""); // Password input
  const [error, setError] = useState(""); // Error message
  const [therapists, setTherapists] = useState([]); // List of therapists
  const navigate = useNavigate();

  // Fetch therapist names from backend
  useEffect(() => {
    const fetchTherapists = async () => {
      try {
        const response = await axios.get("http://localhost:4000/therapists");
        const sortedTherapists = response.data.sort((a, b) =>
          a.name.localeCompare(b.name, "el", { sensitivity: "base" })
        );
        setTherapists(sortedTherapists);
      } catch (err) {
        console.error("Error fetching therapists:", err);
      }
    };

    fetchTherapists();
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await loginUser(role, password); // Use API function

      if (response.data.success) {
        // Redirect based on role
        if (role === "Admin") navigate("/admin-dashboard");
        else if (role === "Secretary") navigate("/secretary-dashboard");
        else navigate(`/therapist-dashboard/${role}`); // Therapist-specific route
      } else {
        setError("Λάθος στοιχεία. Παρακαλώ προσπαθήστε ξανά."); // Error in Greek
      }
    } catch (err) {
      console.error(err);
      setError("Προέκυψε σφάλμα. Παρακαλώ προσπαθήστε αργότερα.");
    }
  };

  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100">
      <form onSubmit={handleLogin} className="bg-white p-6 rounded shadow-md w-80">
        <h2 className="text-xl font-bold mb-4">Σύνδεση</h2> {/* "Login" in Greek */}
        {error && <p className="text-red-500 mb-2">{error}</p>}
        <div className="mb-4">
          <label className="block mb-1">Επιλογή Χρήστη</label> {/* "Select User" */}
          <select value={role} onChange={(e) => setRole(e.target.value)} className="w-full p-2 border rounded" required>
            <option value="">Επιλέξτε Χρήστη</option> {/* "Choose User" */}
            {therapists.map((therapist) => (
              <option key={therapist.id} value={therapist.name}>{therapist.name}</option>
            ))}
            <option value="Admin">Διαχειριστής</option> {/* "Admin" */}
            <option value="Secretary">Γραμματέας</option> {/* "Secretary" */}
          </select>
        </div>
        <div className="mb-4">
          <label className="block mb-1">Κωδικός</label> {/* "Password" */}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full p-2 border rounded" placeholder="Εισάγετε τον κωδικό σας" required />
        </div>
        <button type="submit" className="w-full p-2 bg-blue-500 text-white rounded hover:bg-blue-600">
          Σύνδεση {/* "Login" */}
        </button>
      </form>
    </div>
  );
};

export default Login;
