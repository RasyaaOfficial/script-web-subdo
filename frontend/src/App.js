import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Theme Context
const ThemeContext = React.createContext();

const App = () => {
  const [darkMode, setDarkMode] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      setDarkMode(true);
    }
  }, []);

  useEffect(() => {
    // Apply theme to document
    if (darkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }, [darkMode]);

  const toggleTheme = () => {
    setDarkMode(!darkMode);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <ThemeContext.Provider value={{ darkMode, toggleTheme }}>
      <div className="App">
        <Header user={user} logout={logout} />
        <main className="main-content">
          {!user ? (
            <LoginPage setUser={setUser} setToken={setToken} />
          ) : (
            <Dashboard user={user} />
          )}
        </main>
        <Footer />
      </div>
    </ThemeContext.Provider>
  );
};

// Header Component
const Header = ({ user, logout }) => {
  const { darkMode, toggleTheme } = React.useContext(ThemeContext);

  return (
    <header className="header">
      <div className="header-content">
        <h1 className="logo">Website Subdomain Reseller</h1>
        <div className="header-actions">
          <button onClick={toggleTheme} className="theme-toggle">
            {darkMode ? "🌞" : "🌙"}
          </button>
          {user && (
            <button onClick={logout} className="logout-btn">
              🔑 Logout
            </button>
          )}
        </div>
      </div>
    </header>
  );
};

// Login Component
const LoginPage = ({ setUser, setToken }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    role: 'user'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post(`${API}/auth/login`, formData);
      const { access_token, user } = response.data;
      
      localStorage.setItem('token', access_token);
      setToken(access_token);
      setUser(user);
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>Login to Your Account</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Role</label>
            <select
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
            >
              <option value="user">Pengguna Biasa</option>
              <option value="reseller">Reseller</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          {error && <div className="error-message">{error}</div>}
          <button type="submit" disabled={loading} className="login-btn">
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = ({ user }) => {
  const [activeTab, setActiveTab] = useState('create-subdomain');

  const getDashboardTabs = () => {
    const baseTabs = [
      { id: 'create-subdomain', label: 'Create Subdomain', icon: '🌐' }
    ];

    if (user.role === 'reseller' || user.role === 'admin') {
      baseTabs.push({ id: 'manage-users', label: 'Manage Users', icon: '👥' });
    }

    baseTabs.push({ id: 'subdomain-history', label: 'Subdomain History', icon: '📋' });

    return baseTabs;
  };

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Welcome, {user.nama}</h2>
        <span className="role-badge">{user.role}</span>
      </div>
      
      <div className="dashboard-tabs">
        {getDashboardTabs().map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-icon">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      <div className="dashboard-content">
        {activeTab === 'create-subdomain' && <CreateSubdomainForm />}
        {activeTab === 'manage-users' && (user.role === 'reseller' || user.role === 'admin') && (
          <ManageUsers userRole={user.role} />
        )}
        {activeTab === 'subdomain-history' && <SubdomainHistory />}
      </div>
    </div>
  );
};

// Create Subdomain Form
const CreateSubdomainForm = () => {
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    tld_id: ''
  });
  const [tlds, setTlds] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchTlds();
  }, []);

  const fetchTlds = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API}/settings/tlds`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTlds(response.data);
    } catch (err) {
      console.error('Failed to fetch TLDs:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(`${API}/subdomains`, formData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setMessage({
        type: 'success',
        text: `Success! Created: ${response.data.subdomain} and ${response.data.node_subdomain}`
      });
      
      setFormData({ hostname: '', ip_address: '', tld_id: '' });
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Failed to create subdomain'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container">
      <h3>Create New Subdomain</h3>
      <form onSubmit={handleSubmit} className="subdomain-form">
        <div className="form-group">
          <label>Hostname</label>
          <input
            type="text"
            value={formData.hostname}
            onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
            placeholder="Enter hostname (e.g., mysite)"
            required
          />
        </div>
        
        <div className="form-group">
          <label>IP Address</label>
          <input
            type="text"
            value={formData.ip_address}
            onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
            placeholder="192.168.1.100"
            required
          />
        </div>
        
        <div className="form-group">
          <label>Select TLD</label>
          <select
            value={formData.tld_id}
            onChange={(e) => setFormData({ ...formData, tld_id: e.target.value })}
            required
          >
            <option value="">Choose a TLD...</option>
            {tlds.map(tld => (
              <option key={tld.id} value={tld.id}>
                {tld.tld}
              </option>
            ))}
          </select>
        </div>
        
        {message && (
          <div className={`message ${message.type}`}>
            {message.text}
          </div>
        )}
        
        <button type="submit" disabled={loading} className="submit-btn">
          {loading ? 'Creating...' : 'Create Subdomain'}
        </button>
      </form>
    </div>
  );
};

// Manage Users Component
const ManageUsers = ({ userRole }) => {
  const [users, setUsers] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    nama: '',
    role: 'user'
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (userRole === 'admin') {
      fetchUsers();
    }
  }, [userRole]);

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API}/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsers(response.data);
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      await axios.post(`${API}/users`, formData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setMessage({ type: 'success', text: 'User created successfully!' });
      setFormData({ email: '', password: '', nama: '', role: 'user' });
      setShowForm(false);
      
      if (userRole === 'admin') {
        fetchUsers();
      }
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Failed to create user'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="manage-users">
      <div className="section-header">
        <h3>Manage Users</h3>
        <button onClick={() => setShowForm(!showForm)} className="add-user-btn">
          {showForm ? 'Cancel' : '+ Add User'}
        </button>
      </div>
      
      {showForm && (
        <div className="form-container">
          <h4>Add New User</h4>
          <form onSubmit={handleSubmit} className="user-form">
            <div className="form-row">
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={formData.nama}
                  onChange={(e) => setFormData({ ...formData, nama: e.target.value })}
                  required
                />
              </div>
            </div>
            
            <div className="form-row">
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Role</label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                >
                  <option value="user">Regular User</option>
                  {userRole === 'admin' && <option value="reseller">Reseller</option>}
                </select>
              </div>
            </div>
            
            {message && (
              <div className={`message ${message.type}`}>
                {message.text}
              </div>
            )}
            
            <button type="submit" disabled={loading} className="submit-btn">
              {loading ? 'Creating...' : 'Create User'}
            </button>
          </form>
        </div>
      )}
      
      {userRole === 'admin' && users.length > 0 && (
        <div className="users-table">
          <h4>All Users</h4>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr key={user.id}>
                  <td>{user.nama}</td>
                  <td>{user.email}</td>
                  <td><span className={`role-badge ${user.role}`}>{user.role}</span></td>
                  <td>{new Date(user.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// Subdomain History Component
const SubdomainHistory = () => {
  const [subdomains, setSubdomains] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSubdomains();
  }, []);

  const fetchSubdomains = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API}/subdomains`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSubdomains(response.data);
    } catch (err) {
      console.error('Failed to fetch subdomains:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      // Could add a toast notification here
      alert(`Copied: ${text}`);
    });
  };

  if (loading) {
    return <div className="loading">Loading subdomains...</div>;
  }

  return (
    <div className="subdomain-history">
      <h3>Subdomain History</h3>
      
      {subdomains.length === 0 ? (
        <div className="empty-state">
          <p>No subdomains found. Create your first subdomain!</p>
        </div>
      ) : (
        <div className="subdomains-table">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Node Subdomain</th>
                <th>IP Address</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {subdomains.map(subdomain => (
                <tr key={subdomain.id}>
                  <td>
                    <span className="subdomain-name">{subdomain.subdomain}</span>
                  </td>
                  <td>
                    <span className="subdomain-name">{subdomain.node_subdomain}</span>
                  </td>
                  <td>{subdomain.ip_address}</td>
                  <td>{new Date(subdomain.created_at).toLocaleDateString()}</td>
                  <td>
                    <button
                      onClick={() => copyToClipboard(subdomain.subdomain)}
                      className="copy-btn"
                      title="Copy subdomain"
                    >
                      📋 Copy
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// Footer Component
const Footer = () => {
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        timeZone: 'Asia/Jakarta'
      };
      setCurrentTime(now.toLocaleDateString('id-ID', options));
    };

    updateTime();
    const interval = setInterval(updateTime, 60000); // Update every minute

    return () => clearInterval(interval);
  }, []);

  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-section">
          <h4>Contact</h4>
          <p>Email: rasyaanaufall@gmail.com</p>
          <p>WhatsApp: +62 856-0248-9033</p>
        </div>
        
        <div className="footer-section">
          <p>© 2025 Rasyaa Creative</p>
          <p className="current-date">{currentTime}</p>
        </div>
      </div>
    </footer>
  );
};

export default App;