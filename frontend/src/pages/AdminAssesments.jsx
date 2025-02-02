import React, { useState, useEffect } from "react";
import axios from "axios";

const AdminAssessments = () => {
  const [therapistName, setTherapistName] = useState("");
  const [file, setFile] = useState(null);
  const [assessments, setAssessments] = useState([]);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file || !therapistName) {
      alert("Please select a therapist and a file.");
      return;
    }

    const formData = new FormData();
    formData.append("therapistName", therapistName);
    formData.append("file", file);

    try {
      await axios.post("http://localhost:4000/upload-assessment", formData);
      alert("Assessment uploaded successfully.");
      fetchAssessments(); // Refresh the list
    } catch (error) {
      console.error(error);
      alert("Upload failed.");
    }
  };

  const fetchAssessments = async () => {
    if (!therapistName) return;
    try {
      const res = await axios.get(`http://localhost:4000/list-assessments/${therapistName}`);
      setAssessments(res.data.files || []);
    } catch (error) {
      console.error(error);
      setAssessments([]);
    }
  };

  const deleteAssessment = async (fileName) => {
    try {
      await axios.delete("http://localhost:4000/delete-assessment", {
        data: { therapistName, fileName },
      });
      alert("Assessment deleted.");
      fetchAssessments();
    } catch (error) {
      console.error(error);
      alert("Failed to delete assessment.");
    }
  };

  return (
    <div>
      <h2>Διαχείριση Αξιολογήσεων</h2>

      <label>Επιλέξτε Θεραπευτή:</label>
      <input type="text" value={therapistName} onChange={(e) => setTherapistName(e.target.value)} placeholder="Όνομα θεραπευτή" />

      <form onSubmit={handleUpload}>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <button type="submit">Ανέβασμα</button>
      </form>

      <button onClick={fetchAssessments}>Προβολή Αξιολογήσεων</button>

      {assessments.length > 0 && (
        <ul>
          {assessments.map((file, index) => (
            <li key={index}>
              {file} <button onClick={() => deleteAssessment(file)}>Διαγραφή</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default AdminAssessments;
