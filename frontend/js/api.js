/**
 * FILE NAME: api.js
 * PURPOSE: Frontend API Client communicating with FastAPI backend endpoints.
 */

const API_BASE = "";

const API = {
  // Token helper
  getToken() {
    return localStorage.getItem("phishguard_token") || "";
  },
  setToken(token) {
    localStorage.setItem("phishguard_token", token);
  },
  clearToken() {
    localStorage.removeItem("phishguard_token");
    localStorage.removeItem("phishguard_user");
  },

  // Auth Endpoints
  async register(username, password, role) {
    const res = await fetch(`${API_BASE}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Registration failed" }));
      throw new Error(err.detail || "Registration failed");
    }
    return res.json();
  },

  async login(username, password) {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Invalid credentials" }));
      throw new Error(err.detail || "Login failed");
    }
    return res.json();
  },

  async logout() {
    const token = this.getToken();
    if (token) {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      }).catch(() => {});
    }
    this.clearToken();
  },

  async getCurrentUser() {
    const token = this.getToken();
    if (!token) return null;
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.authenticated ? data.user : null;
  },

  // Analyze Email
  async analyzeEmail(payload) {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Analysis failed" }));
      throw new Error(err.detail || "Server error during analysis");
    }
    return res.json();
  },

  // Analyze Single URL
  async analyzeURL(url) {
    const res = await fetch(`${API_BASE}/api/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "URL analysis failed" }));
      throw new Error(err.detail || "Server error during URL analysis");
    }
    return res.json();
  },

  // Fetch Dashboard Stats
  async getDashboardStats() {
    const res = await fetch(`${API_BASE}/api/dashboard/stats`);
    if (!res.ok) throw new Error("Failed to fetch dashboard metrics");
    return res.json();
  },

  // Fetch Analysis History
  async getHistory(classification = "", search = "") {
    let url = `${API_BASE}/api/analyses?limit=100`;
    if (classification) url += `&classification=${encodeURIComponent(classification)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error("Failed to fetch history");
    return res.json();
  },

  // Fetch Specific Analysis Detail
  async getAnalysisDetail(analysisId) {
    const res = await fetch(`${API_BASE}/api/analyses/${encodeURIComponent(analysisId)}`);
    if (!res.ok) throw new Error("Failed to fetch analysis details");
    return res.json();
  },

  // Delete Analysis
  async deleteAnalysis(analysisId) {
    const res = await fetch(`${API_BASE}/api/analyses/${encodeURIComponent(analysisId)}`, {
      method: "DELETE"
    });
    if (!res.ok) throw new Error("Failed to delete analysis");
    return res.json();
  },

  // Fetch Awareness Content
  async getAwarenessData() {
    const res = await fetch(`${API_BASE}/api/awareness/lessons`);
    if (!res.ok) throw new Error("Failed to fetch awareness content");
    return res.json();
  },

  // Fetch Simulation Samples
  async getSimulationTemplates() {
    const res = await fetch(`${API_BASE}/api/simulation/templates`);
    if (!res.ok) throw new Error("Failed to fetch simulation templates");
    return res.json();
  }
};
