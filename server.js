require('dotenv').config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const allowedOrigins = [
    'http://localhost:3000',
    'https://asset-management-blue.vercel.app'
  ];

app.use(cors()); // CORS untuk frontend
app.use(express.json()); // 🔥 Penting untuk membaca request body JSON
app.use(express.urlencoded({ extended: true })); // 🔥 Tambahkan ini untuk menangani form-data

// Cek apakah middleware berjalan
app.use((req, res, next) => {
    console.log("📝 Middleware: Request diterima dengan method", req.method, "di", req.url);
    console.log("📥 Request Body:", req.body);
    next();
});

// Koneksi ke MySQL Railway
const db = mysql.createConnection({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT
});


db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("Connected to MySQL");
    }
});

// Secret Key untuk JWT
const SECRET_KEY = process.env.SECRET_KEY; // HARUS SAMA!

// Secret Key untuk JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    
   // console.log("Token Received:", authHeader); // ✅ Cek token yang diterima

    if (!authHeader) {
        return res.status(403).json({ error: "Unauthorized, no token provided" });
    }

    const tokenParts = authHeader.split(" ");
    if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
        return res.status(401).json({ error: "Invalid token format" });
    }

    const token = tokenParts[1]; // Ambil token setelah "Bearer"

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.error("JWT Verify Error:", err.message); // ✅ Log error JWT
            return res.status(401).json({ error: "Invalid token" });
        }

       // console.log("Decoded Token:", decoded); // ✅ Log isi token setelah decode
        req.user = decoded; // Simpan ke request
        next();
    });
};


app.get("/", (req, res) => {
    res.json({ message: "Backend API is running 🚀" });
});

app.listen(5000, "0.0.0.0", () => {
    console.log("Server running on port 5000 and accessible via network");
});






// ✅ REGISTER USER (Dengan Validasi Email Unik & Password Minimal 6 Karakter)
// ✅ REGISTER USER (Role Default = 3)
app.post("/register", (req, res) => {
    const { nama, email, password, perusahaan_id } = req.body;  // 🛑 Hapus role_id dari input user

    // Validasi minimal password
    if (password.length < 6) {
        return res.status(400).json({ error: "Password harus minimal 6 karakter" });
    }

    // Cek apakah email sudah terdaftar
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length > 0) return res.status(400).json({ error: "Email sudah terdaftar!" });

        // Hash password dan simpan user baru dengan role_id = 3 (Staff)
        const hashedPassword = bcrypt.hashSync(password, 10);
        db.query(
            "INSERT INTO users (nama, email, password, role_id, perusahaan_id) VALUES (?, ?, ?, ?, ?)",
            [nama, email, hashedPassword, 3, perusahaan_id],  // 🔥 role_id DISET KE 3
            (err, result) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: "User berhasil terdaftar sebagai Staff" });
            }
        );
    });
});



// 🔹 LOGIN USER & GENERATE TOKEN
app.post("/login", (req, res) => {
    const { email, password, perusahaan_id } = req.body;

    db.query(`
        SELECT users.id, users.nama AS nama_user, users.password, users.role_id, 
               users.perusahaan_id, companies.nama_perusahaan
        FROM users
        JOIN companies ON users.perusahaan_id = companies.id
        WHERE users.email = ? AND users.perusahaan_id = ?
    `, [email, perusahaan_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0) return res.status(401).json({ error: "Email atau perusahaan tidak cocok" });

        const user = results[0];

        console.log("User Found in DB:", user); // ✅ Debug apakah perusahaan_id ada

        const passwordMatch = bcrypt.compareSync(password, user.password);

        if (!passwordMatch) return res.status(401).json({ error: "Password salah" });

        // Jika login berhasil, buat token
        const token = jwt.sign({
            id: user.id,
            nama_user: user.nama_user,
            perusahaan_id: user.perusahaan_id, // ✅ Pastikan masuk ke token
            nama_perusahaan: user.nama_perusahaan,
            role_id: user.role_id
        }, SECRET_KEY, { expiresIn: "2h" });

        res.json({ token });
    });
});



// 🔹 GET USER BERDASARKAN ID (Hanya bisa melihat data user dalam `company_id` mereka)
app.get("/users/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const company_id = req.user.perusahaan_id;

    db.query("SELECT id, nama, email, role_id, perusahaan_id FROM users WHERE id = ? AND perusahaan_id = ?", 
    [id, company_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: "User not found or unauthorized" });
        res.json(results[0]);
    });
});



// 🔹 GANTI PASSWORD (Hanya untuk user sendiri)
app.post("/change-password", verifyToken, (req, res) => {
    const { newPassword } = req.body;
    const hashedPassword = bcrypt.hashSync(newPassword, 10);

    db.query("UPDATE users SET password = ? WHERE id = ?", 
    [hashedPassword, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Password berhasil diubah" });
    });
});


// 🔹 GET ALL USERS (Hanya melihat user dalam `company_id` mereka kecuali admin)
app.get("/users", verifyToken, (req, res) => {
    let query = `
        SELECT users.id, users.nama, users.email, users.role_id, users.perusahaan_id, 
               roles.role_name, companies.nama_perusahaan 
        FROM users 
        LEFT JOIN roles ON users.role_id = roles.id 
        LEFT JOIN companies ON users.perusahaan_id = companies.id`;

    let params = [];

    if (req.user.role_id !== 1) {
        query += " WHERE users.perusahaan_id = ?";
        params.push(req.user.perusahaan_id);
    }

    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});


// 🔹 ADD USER (Admin bisa menambahkan user ke perusahaan lain, user biasa hanya ke `company_id` mereka)
app.post("/users", verifyToken, (req, res) => {
    const { nama, email, password, role_id, perusahaan_id } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    if (req.user.role_id !== 1 && perusahaan_id !== req.user.perusahaan_id) {
        return res.status(403).json({ error: "Access Denied! Tidak bisa menambahkan user ke perusahaan lain." });
    }

    db.query("INSERT INTO users (nama, email, password, role_id, perusahaan_id) VALUES (?, ?, ?, ?, ?)", 
    [nama, email, hashedPassword, role_id, perusahaan_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User added successfully" });
    });
});



// 🔹 UPDATE USER (Admin bisa edit semua user, user biasa hanya dalam `company_id` mereka)
app.put("/users/:id", verifyToken, (req, res) => {
    const { nama, email, role_id, perusahaan_id } = req.body;

    if (req.user.role_id !== 1 && perusahaan_id !== req.user.perusahaan_id) {
        return res.status(403).json({ error: "Access Denied! Tidak bisa mengedit user dari perusahaan lain." });
    }

    db.query("UPDATE users SET nama = ?, email = ?, role_id = ?, perusahaan_id = ? WHERE id = ?", 
    [nama, email, role_id, perusahaan_id, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User updated successfully" });
    });
});



// 🔹 DELETE USER (Admin hanya bisa menghapus user dalam `company_id` mereka)
app.delete("/users/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) return res.status(403).json({ error: "Access Denied" });

    db.query("DELETE FROM users WHERE id = ? AND perusahaan_id = ?", 
    [req.params.id, req.user.perusahaan_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(403).json({ error: "Tidak diizinkan menghapus user dari perusahaan lain!" });
        res.json({ message: "User deleted successfully" });
    });
});


app.get("/roles", verifyToken, (req, res) => {
    db.query("SELECT * FROM roles", (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// 🔹 GET COMPANIES (Perusahaan)
app.get("/companies", (req, res) => {
    db.query("SELECT * FROM companies", (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: err.message });
        }
        console.log("Data perusahaan berhasil diambil:", results); // 🔥 Debugging
        res.json(results);
    });
});


// POST: Tambah perusahaan baru
app.post("/companies", (req, res) => {
    const { kode, nama_perusahaan } = req.body;
    db.query(
      "INSERT INTO companies (kode, nama_perusahaan) VALUES (?, ?)",
      [kode, nama_perusahaan],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Perusahaan ditambahkan" });
      }
    );
  });

  // PUT: Update perusahaan
  app.put("/companies/:id", (req, res) => {
    const { kode, nama_perusahaan } = req.body;
    db.query(
      "UPDATE companies SET kode = ?, nama_perusahaan = ? WHERE id = ?",
      [kode, nama_perusahaan, req.params.id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Perusahaan diperbarui" });
      }
    );
  });

  // DELETE: Hapus perusahaan
  app.delete("/companies/:id", (req, res) => {
    db.query("DELETE FROM companies WHERE id = ?", [req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Perusahaan dihapus" });
    });
  });


// 🔹 GET COMPANIES (Untuk Form Login)
app.get("/companies/list", (req, res) => {
    db.query("SELECT id, nama_perusahaan FROM companies", (err, results) => {
        if (err) {
            console.error("Database error:", err); // 🔥 Debug error
            return res.status(500).json({ error: err.message });
        }
        console.log("Data perusahaan:", results); // 🔥 Debug hasil query
        res.json(results);
    });
});





// 🔹 GET ALL DEPARTMENTS (Hanya untuk company_id yang sama dengan user)
app.get("/departments", verifyToken, (req, res) => {
    const perusahaan_id = req.user.perusahaan_id; // Ambil dari token

    console.log("Company ID dari Token:", perusahaan_id); // ✅ Debug untuk memastikan perusahaan_id ada

    if (!perusahaan_id) {
        return res.status(400).json({ error: "Company ID not found in token" });
    }

    db.query(
        "SELECT * FROM departments WHERE company_id = ? ORDER BY CAST(kode AS UNSIGNED) ASC",
        [perusahaan_id],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: err.message });
            }
            console.log("✅ Data Departemen Ditemukan:", results); // ✅ Debug data hasil query
            res.json(results);
        }
    );
});




// 🔹 ADD DEPARTMENT (Hanya untuk company_id user)
app.post("/departments", verifyToken, (req, res) => {
    const { kode, nama_departments } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user
    
    console.log("Company ID dari Token:", company_id); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_departments) {
        return res.status(400).json({ error: "Kode dan Nama Departemen wajib diisi!" });
    }

    db.query(
        "INSERT INTO departments (company_id, kode, nama_departments) VALUES (?, ?, ?)",
        [company_id, kode, nama_departments],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menambahkan departemen:", err);
                return res.status(500).json({ error: err.message });
            }
            console.log("✅ Departemen Berhasil Ditambahkan:", result);
            res.json({ message: "Departemen berhasil ditambahkan!" });
        }
    );
});


// 🔹 UPDATE DEPARTMENT (Hanya bisa edit departemen dalam company_id user)
app.put("/departments/:id", verifyToken, (req, res) => {
    const { kode, nama_departments } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user
    
    console.log("Company ID dari Token:", company_id, "Department ID:", req.params.id); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_departments) {
        return res.status(400).json({ error: "Kode dan Nama Departemen wajib diisi!" });
    }

    db.query(
        "UPDATE departments SET kode = ?, nama_departments = ? WHERE id = ? AND company_id = ?",
        [kode, nama_departments, req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal memperbarui departemen:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan mengedit departemen dari perusahaan lain!" });
            }
            console.log("✅ Departemen Berhasil Diperbarui:", result);
            res.json({ message: "Departemen berhasil diperbarui!" });
        }
    );
});

// 🔹 DELETE DEPARTMENT (Hanya Admin dan hanya dari company_id user)
app.delete("/departments/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus departemen." });
    }

    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Department ID:", req.params.id); // ✅ Debugging

    db.query("DELETE FROM departments WHERE id = ? AND company_id = ?", [req.params.id, company_id], (err, result) => {
        if (err) {
            console.error("❌ Gagal menghapus departemen:", err);
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus departemen dari perusahaan lain!" });
        }
        console.log("✅ Departemen Berhasil Dihapus:", result);
        res.json({ message: "Departemen berhasil dihapus!" });
    });
});





// 🔹 GET ALL LOCATIONS (Hanya untuk company_id yang sama dengan user)
app.get("/locations", verifyToken, (req, res) => {
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id); // ✅ Debug perusahaan_id dari token

    if (!company_id) {
        return res.status(400).json({ error: "Company ID not found in token" });
    }

    db.query("SELECT * FROM locations WHERE company_id = ? ORDER BY CAST(kode AS UNSIGNED) ASC", [company_id], (err, results) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log("✅ Data Lokasi Ditemukan:", results); // ✅ Debug hasil query
        res.json(results);
    });
});


// 🔹 ADD LOCATION (Hanya untuk company_id yang sama dengan user)
app.post("/locations", verifyToken, (req, res) => {
    console.log("Request Diterima:", req.body); // ✅ Debug log
    const { kode, nama_lokasi } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_lokasi) {
        return res.status(400).json({ error: "Kode dan Nama Lokasi wajib diisi!" });
    }

    db.query(
        "INSERT INTO locations (company_id, kode, nama_lokasi) VALUES (?, ?, ?)",
        [company_id, kode, nama_lokasi],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menambahkan lokasi:", err);
                return res.status(500).json({ error: err.message });
            }
            console.log("✅ Lokasi Berhasil Ditambahkan:", result);
            res.json({ message: "Lokasi berhasil ditambahkan!" });
        }
    );
});


// 🔹 UPDATE LOCATION (Hanya bisa edit lokasi dalam company_id user)
app.put("/locations/:id", verifyToken, (req, res) => {
    const { kode, nama_lokasi } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id, "Location ID:", req.params.id); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_lokasi) {
        return res.status(400).json({ error: "Kode dan Nama Lokasi wajib diisi!" });
    }

    db.query(
        "UPDATE locations SET kode = ?, nama_lokasi = ? WHERE id = ? AND company_id = ?",
        [kode, nama_lokasi, req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal memperbarui lokasi:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan mengedit lokasi dari perusahaan lain!" });
            }
            console.log("✅ Lokasi Berhasil Diperbarui:", result);
            res.json({ message: "Lokasi berhasil diperbarui!" });
        }
    );
});


// 🔹 DELETE LOCATION (Hanya Admin dan hanya dari company_id user)
app.delete("/locations/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus lokasi." });
    }

    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Location ID:", req.params.id); // ✅ Debugging

    db.query("DELETE FROM locations WHERE id = ? AND company_id = ?", [req.params.id, company_id], (err, result) => {
        if (err) {
            console.error("❌ Gagal menghapus lokasi:", err);
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus lokasi dari perusahaan lain!" });
        }
        console.log("✅ Lokasi Berhasil Dihapus:", result);
        res.json({ message: "Lokasi berhasil dihapus!" });
    });
});




// 🔹 GET ALL CATEGORIES (Hanya untuk company_id yang sama dengan user)
app.get("/categories", verifyToken, (req, res) => {
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token

    console.log("Company ID dari Token:", company_id); // ✅ Debug perusahaan_id dari token

    if (!company_id) {
        return res.status(400).json({ error: "Company ID not found in token" });
    }

    db.query("SELECT * FROM asset_categories WHERE company_id = ? ORDER BY CAST(kode AS UNSIGNED) ASC", [company_id], (err, results) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log("✅ Data Kategori Ditemukan:", results); // ✅ Debug hasil query
        res.json(results);
    });
});


// 🔹 ADD CATEGORY (Hanya untuk company_id yang sama dengan user)
app.post("/categories", verifyToken, (req, res) => {
    const { kode, nama_kategori } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id, "Kategori Diterima:", req.body); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_kategori) {
        return res.status(400).json({ error: "Kode dan Nama Kategori wajib diisi!" });
    }

    db.query(
        "INSERT INTO asset_categories (company_id, kode, nama_kategori) VALUES (?, ?, ?)",
        [company_id, kode, nama_kategori],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menambahkan kategori:", err);
                return res.status(500).json({ error: err.message });
            }
            console.log("✅ Kategori Berhasil Ditambahkan:", result);
            res.json({ message: "Kategori berhasil ditambahkan!" });
        }
    );
});


// 🔹 UPDATE CATEGORY (Hanya bisa edit kategori dalam company_id user)
app.put("/categories/:id", verifyToken, (req, res) => {
    const { kode, nama_kategori } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id, "Kategori ID:", req.params.id, "Kategori Update:", req.body); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kode || !nama_kategori) {
        return res.status(400).json({ error: "Kode dan Nama Kategori wajib diisi!" });
    }

    db.query(
        "UPDATE asset_categories SET kode = ?, nama_kategori = ? WHERE id = ? AND company_id = ?",
        [kode, nama_kategori, req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal memperbarui kategori:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan mengedit kategori dari perusahaan lain!" });
            }
            console.log("✅ Kategori Berhasil Diperbarui:", result);
            res.json({ message: "Kategori berhasil diperbarui!" });
        }
    );
});


// 🔹 DELETE CATEGORY (Hanya Admin dan hanya dari company_id user)
app.delete("/categories/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus kategori." });
    }

    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Kategori ID:", req.params.id); // ✅ Debugging

    db.query("DELETE FROM asset_categories WHERE id = ? AND company_id = ?", [req.params.id, company_id], (err, result) => {
        if (err) {
            console.error("❌ Gagal menghapus kategori:", err);
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus kategori dari perusahaan lain!" });
        }
        console.log("✅ Kategori Berhasil Dihapus:", result);
        res.json({ message: "Kategori berhasil dihapus!" });
    });
});




// // 🔹 GET ALL TYPES (Hanya untuk company_id yang sama dengan user)
// app.get("/types", verifyToken, (req, res) => {
//     const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

//     console.log("Company ID dari Token:", company_id); // ✅ Debug perusahaan_id dari token

//     if (!company_id) {
//         return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
//     }

//     db.query(
//         `SELECT asset_types.* FROM asset_types 
//          JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
//          WHERE asset_categories.company_id = ?`, 
//         [company_id], 
//         (err, results) => {
//             if (err) {
//                 console.error("❌ Database error:", err);
//                 return res.status(500).json({ error: err.message });
//             }

//             console.log("✅ Data Types Ditemukan:", results); // ✅ Debug hasil query
//             res.json(results);
//         }
//     );
// });


// 🔹 GET ALL TYPES (Hanya untuk company_id yang sama dengan user)
app.get("/types", verifyToken, (req, res) => {
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id); // ✅ Debug perusahaan_id dari token

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    db.query(
        `SELECT asset_types.* FROM asset_types 
         JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
         WHERE asset_categories.company_id = ?
         ORDER BY CAST(asset_types.kategori_id AS UNSIGNED) ASC`,
        [company_id], 
        (err, results) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: err.message });
            }

            console.log("✅ Data Types Ditemukan:", results); // ✅ Debug hasil query
            res.json(results);
        }
    );
});



// 🔹 ADD TYPE (Hanya untuk company_id yang sama dengan user)
app.post("/types", verifyToken, (req, res) => {
    const { kategori_id, kode, nama_asset } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id, "Kategori ID:", kategori_id, "Data Type Diterima:", req.body); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kategori_id || !kode || !nama_asset) {
        return res.status(400).json({ error: "Semua field wajib diisi!" });
    }

    // Pastikan kategori milik perusahaan yang sama
    db.query(
        "SELECT * FROM asset_categories WHERE id = ? AND company_id = ?", 
        [kategori_id, company_id], 
        (err, results) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: err.message });
            }
            if (results.length === 0) {
                return res.status(403).json({ error: "❌ Kategori tidak ditemukan atau tidak diizinkan!" });
            }

            // Jika kategori valid, lanjutkan insert dengan `company_id`
            db.query(
                "INSERT INTO asset_types (kategori_id, kode, nama_asset, company_id) VALUES (?, ?, ?, ?)",
                [kategori_id, kode, nama_asset, company_id], // ✅ Tambahkan company_id
                (err, result) => {
                    if (err) {
                        console.error("❌ Gagal menambahkan jenis aset:", err);
                        return res.status(500).json({ error: err.message });
                    }
                    console.log("✅ Jenis Aset Berhasil Ditambahkan:", result);
                    res.json({ message: "Jenis aset berhasil ditambahkan!" });
                }
            );
        }
    );
});




// 🔹 UPDATE TYPE (Hanya bisa edit jenis aset dalam company_id user)
app.put("/types/:id", verifyToken, (req, res) => {
    const { kategori_id, kode, nama_asset } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Company ID dari Token:", company_id, "Kategori ID:", kategori_id, "Jenis ID:", req.params.id, "Data Update:", req.body); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    if (!kategori_id || !kode || !nama_asset) {
        return res.status(400).json({ error: "Semua field wajib diisi!" });
    }

    db.query(
        `UPDATE asset_types 
         JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
         SET asset_types.kategori_id = ?, asset_types.kode = ?, asset_types.nama_asset = ?
         WHERE asset_types.id = ? AND asset_categories.company_id = ?`,
        [kategori_id, kode, nama_asset, req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal memperbarui jenis aset:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan mengedit jenis aset dari perusahaan lain!" });
            }
            console.log("✅ Jenis Aset Berhasil Diperbarui:", result);
            res.json({ message: "Jenis aset berhasil diperbarui!" });
        }
    );
});


// 🔹 DELETE TYPE (Hanya Admin dan hanya dari company_id user)
app.delete("/types/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus jenis aset." });
    }

    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Jenis ID:", req.params.id); // ✅ Debugging

    db.query(
        `DELETE asset_types FROM asset_types 
         JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
         WHERE asset_types.id = ? AND asset_categories.company_id = ?`,
        [req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menghapus jenis aset:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan menghapus jenis aset dari perusahaan lain!" });
            }
            console.log("✅ Jenis Aset Berhasil Dihapus:", result);
            res.json({ message: "Jenis aset berhasil dihapus!" });
        }
    );
});









app.get("/subtypes", verifyToken, (req, res) => {
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user
    const page = parseInt(req.query.page) || 1; // Default halaman pertama
    const limit = parseInt(req.query.limit) || 10; // Default 10 data per halaman
    const offset = (page - 1) * limit;

    console.log("Company ID dari Token:", company_id, "Halaman:", page, "Limit:", limit); // ✅ Debugging

    if (!company_id) {
        return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
    }

    db.query(
        `SELECT asset_subtypes.* FROM asset_subtypes
         JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id
         WHERE asset_types.company_id = ?
         ORDER BY CAST(asset_subtypes.kode AS UNSIGNED) ASC
         LIMIT ? OFFSET ?`,
        [company_id, limit, offset],
        (err, results) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: err.message });
            }

            db.query(
                `SELECT COUNT(*) AS total FROM asset_subtypes
                 JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id
                 WHERE asset_types.company_id = ?`,
                [company_id],
                (err, countResult) => {
                    if (err) {
                        console.error("❌ Database count error:", err);
                        return res.status(500).json({ error: err.message });
                    }

                    console.log("✅ Data Subtypes Ditemukan:", results); // ✅ Debug hasil query
                    res.json({
                        data: results,
                        total: countResult[0].total,
                        totalPages: Math.ceil(countResult[0].total / limit),
                        currentPage: page
                    });
                }
            );
        }
    );
});


app.post("/subtypes", verifyToken, (req, res) => {
    const { jenis_id, kode, nama_subaset } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token

    console.log("📥 Data Subtype Diterima:", req.body);

    if (!company_id) {
        return res.status(400).json({ error: "❌ Company ID tidak ditemukan dalam token!" });
    }

    if (!jenis_id || !kode || !nama_subaset) {
        return res.status(400).json({ error: "❌ Semua field wajib diisi!" });
    }

    // Pastikan jenis_id valid dan milik perusahaan yang sama
    db.query(
        `SELECT * FROM asset_types WHERE id = ? AND company_id = ?`,
        [jenis_id, company_id],
        (err, results) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: err.message });
            }
            if (results.length === 0) {
                return res.status(403).json({ error: "Jenis aset tidak ditemukan atau tidak diizinkan!" });
            }

            // Insert data ke tabel asset_subtypes
            db.query(
                "INSERT INTO asset_subtypes (jenis_id, kode, nama_subaset, company_id) VALUES (?, ?, ?, ?)",
                [jenis_id, kode, nama_subaset, company_id],
                (err, result) => {
                    if (err) {
                        console.error("❌ Gagal menambah sub-jenis:", err);
                        return res.status(500).json({ error: err.message });
                    }
                    console.log("✅ Sub-jenis berhasil ditambahkan:", result);
                    res.json({ message: "Sub-jenis berhasil ditambahkan!" });
                }
            );
        }
    );
});



app.put("/subtypes/:id", verifyToken, (req, res) => {
    const { jenis_id, kode, nama_subaset } = req.body;
    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    if (!jenis_id || !kode || !nama_subaset) {
        return res.status(400).json({ error: "❌ Semua field wajib diisi!" });
    }

    db.query(
        `UPDATE asset_subtypes 
         JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id 
         SET asset_subtypes.jenis_id = ?, asset_subtypes.kode = ?, asset_subtypes.nama_subaset = ?
         WHERE asset_subtypes.id = ? AND asset_types.company_id = ?`,
        [jenis_id, kode, nama_subaset, req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal memperbarui sub-jenis:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan mengedit sub-jenis dari perusahaan lain!" });
            }
            console.log("✅ Sub-jenis berhasil diperbarui:", result);
            res.json({ message: "Sub-jenis berhasil diperbarui!" });
        }
    );
});



app.delete("/subtypes/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus sub-jenis aset." });
    }

    const company_id = req.user.perusahaan_id; // Ambil company_id dari token user

    console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Subtype ID:", req.params.id); // ✅ Debugging

    db.query(
        `DELETE asset_subtypes FROM asset_subtypes 
         JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id 
         WHERE asset_subtypes.id = ? AND asset_types.company_id = ?`,
        [req.params.id, company_id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menghapus sub-jenis aset:", err);
                return res.status(500).json({ error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(403).json({ error: "❌ Tidak diizinkan menghapus sub-jenis aset dari perusahaan lain!" });
            }
            console.log("✅ Sub-Jenis Aset Berhasil Dihapus:", result);
            res.json({ message: "Sub-jenis aset berhasil dihapus!" });
        }
    );
});



// ✅ GET ASSETS (Filter Perusahaan, Status, Join, Pagination)
app.get("/assets", verifyToken, (req, res) => {
    console.log("🔵 API /assets terpanggil!");

    const perusahaan_id = req.user.perusahaan_id; // Dari token login
    const role_id = req.user.role_id; // Role user

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const status = req.query.status === "deleted" ? "deleted" : "active"; // 🔹 Filter berdasarkan status

    // ✅ Query dengan LEFT JOIN
    let query = `
SELECT 
    assets.id, 
    assets.kode_asset, 
    assets.status,
    companies.kode AS kode_perusahaan,
    companies.nama_perusahaan,
    departments.nama_departments,
    locations.nama_lokasi,
    asset_types.nama_asset AS jenis_aset,
    asset_subtypes.nama_subaset AS sub_jenis_aset,
    assets.qr_code
FROM assets
LEFT JOIN companies ON assets.kode_perusahaan = companies.id
LEFT JOIN departments ON assets.kode_departemen = departments.id
LEFT JOIN locations ON assets.kode_lokasi = locations.kode
LEFT JOIN asset_types ON assets.jenis_id = asset_types.id
LEFT JOIN asset_subtypes ON assets.subjenis_id = asset_subtypes.kode 
  AND asset_subtypes.jenis_id = asset_types.id -- 🔹 JOIN berdasarkan jenis_id
WHERE assets.status = ?`; 

    let params = [status];

    // ✅ Jika user bukan admin, filter berdasarkan perusahaan
    if (role_id !== 1) {
        query += " AND assets.kode_perusahaan = ?";
        params.push(perusahaan_id);
    }

    // ✅ Tambahkan sorting & pagination
    query += " ORDER BY assets.id DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    console.log("🔹 QUERY yang dikirim ke database:", query);

    db.query(query, params, (err, results) => {
        if (err) {
            console.error("❌ Error saat mengambil data aset:", err);
            return res.status(500).json({ error: err.message });
        }

        // ✅ Ambil total aset berdasarkan filter status
        let countQuery = "SELECT COUNT(*) AS total FROM assets WHERE status = ?";
        let countParams = [status];

        if (role_id !== 1) {
            countQuery += " AND kode_perusahaan = ?";
            countParams.push(perusahaan_id);
        }

        db.query(countQuery, countParams, (err, countResult) => {
            if (err) {
                console.error("❌ Count error:", err);
                return res.status(500).json({ error: err.message });
            }

            console.log("✅ Data yang dikirim ke frontend:", JSON.stringify(results, null, 2));

            res.json({
                data: results || [], // Data aset
                total: countResult[0].total, // Total data
                totalPages: Math.ceil(countResult[0].total / limit),
                currentPage: page
            });
        });
    });
});









// //Simpan Asset (no urut berdasarkan kode_perusahaan)
// const QRCode = require("qrcode");

// app.post("/assets", verifyToken, async (req, res) => {
//     console.log("🔍 Data yang diterima dari frontend:", req.body);

//     const { kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, deskripsi } = req.body;
//     const company_id = req.user.perusahaan_id;

//     if (!company_id || !kode_departemen || !kode_lokasi || !kategori_id || !jenis_id || !subjenis_id) {
//         return res.status(400).json({ error: "❌ Semua field kecuali deskripsi wajib diisi!" });
//     }

//     // **Ubah deskripsi kosong jadi NULL**
//     const deskripsiFinal = deskripsi && deskripsi.trim() !== "" ? deskripsi : null;
//     const kode_departemen_aset = kode_departemen.toUpperCase();

//     db.query(`SELECT kode FROM departments WHERE id = ?`, [kode_departemen], async (err, deptResult) => {
//         if (err) {
//             console.error("❌ Database error saat mengecek departemen:", err);
//             return res.status(500).json({ error: err.message });
//         }
//         if (deptResult.length === 0) {
//             return res.status(404).json({ error: "❌ Departemen tidak ditemukan!" });
//         }

//         db.query(`SELECT id, kode FROM companies WHERE id = ?`, [company_id], async (err, companyResult) => {
//             if (err) {
//                 console.error("❌ Database error saat mengambil kode perusahaan:", err);
//                 return res.status(500).json({ error: err.message });
//             }
//             if (companyResult.length === 0) {
//                 return res.status(404).json({ error: "❌ Perusahaan tidak ditemukan!" });
//             }

//             const kode_perusahaan = companyResult[0].id;
//             const kode_perusahaan_aset = companyResult[0].kode.toUpperCase();

//             db.query(`SELECT kode FROM asset_types WHERE id = ?`, [jenis_id], async (err, jenisResult) => {
//                 if (err) {
//                     console.error("❌ Database error saat mengambil kode jenis aset:", err);
//                     return res.status(500).json({ error: err.message });
//                 }
//                 if (jenisResult.length === 0) {
//                     return res.status(404).json({ error: "❌ Jenis aset tidak ditemukan!" });
//                 }

//                 const kode_jenis = jenisResult[0].kode.toUpperCase();

//                 // 🔹 Ambil `kode` dari subjenis, bukan `id`
//                 db.query(`SELECT kode FROM asset_subtypes WHERE id = ?`, [subjenis_id], async (err, subjenisResult) => {
//                     if (err) {
//                         console.error("❌ Database error saat mengambil kode sub-jenis:", err);
//                         return res.status(500).json({ error: err.message });
//                     }
//                     if (subjenisResult.length === 0) {
//                         return res.status(404).json({ error: "❌ Sub-jenis aset tidak ditemukan!" });
//                     }

//                     const kode_subjenis = subjenisResult[0].kode.toUpperCase();

//                     db.query(
//                         `SELECT COALESCE(MAX(CAST(nomor_urut AS UNSIGNED)), 0) AS last_nomor FROM assets WHERE kode_perusahaan = ?`,
//                         [kode_perusahaan],
//                         async (err, result) => {
//                             if (err) {
//                                 console.error("❌ Database error saat mengambil nomor urut:", err);
//                                 return res.status(500).json({ error: err.message });
//                             }

//                             let nomor_urut = parseInt(result[0].last_nomor, 10) + 1;
//                             let nomor_urut_format = String(nomor_urut).padStart(3, "0");

//                             let kode_asset = `${kode_perusahaan_aset}${kode_departemen_aset}${kode_lokasi}${kategori_id}${kode_jenis}${kode_subjenis}${nomor_urut_format}`;

//                             const qrCodeData = await QRCode.toDataURL(kode_asset);

//                             db.query(
//                                 `INSERT INTO assets (kode_perusahaan, kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, nomor_urut, kode_asset, deskripsi, qr_code) 
//                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//                                 [kode_perusahaan, kode_departemen, kode_lokasi, kategori_id, jenis_id, kode_subjenis, nomor_urut, kode_asset, deskripsiFinal, qrCodeData],
//                                 (err, result) => {
//                                     if (err) {
//                                         console.error("❌ Gagal menambahkan aset:", err);
//                                         return res.status(500).json({ error: err.message });
//                                     }
//                                     res.json({ message: "✅ Aset berhasil ditambahkan!", kode_asset, qrCodeData });
//                                 }
//                             );
//                         }
//                     );
//                 });
//             });
//         });
//     });
// });



const QRCode = require("qrcode");

app.post("/assets", verifyToken, async (req, res) => {
    console.log("🔍 Data yang diterima dari frontend:", req.body);

    const { kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, deskripsi } = req.body;
    const company_id = req.user.perusahaan_id;

    if (!company_id || !kode_departemen || !kode_lokasi || !kategori_id || !jenis_id || !subjenis_id) {
        return res.status(400).json({ error: "❌ Semua field kecuali deskripsi wajib diisi!" });
    }

    const deskripsiFinal = deskripsi && deskripsi.trim() !== "" ? deskripsi : null;

    // **Ambil ID departemen dari database**
    db.query(`SELECT id FROM departments WHERE kode = ? AND company_id = ?`, [kode_departemen, company_id], async (err, deptResult) => {
        if (err) {
            console.error("❌ Database error saat mengecek departemen:", err);
            return res.status(500).json({ error: err.message });
        }
        if (deptResult.length === 0) {
            return res.status(404).json({ error: "❌ Departemen tidak ditemukan!" });
        }
        const departemen_id = deptResult[0].id; // Ambil ID departemen yang benar

        // **Ambil kode perusahaan**
        db.query(`SELECT kode FROM companies WHERE id = ?`, [company_id], async (err, companyResult) => {
            if (err) {
                console.error("❌ Database error saat mengambil kode perusahaan:", err);
                return res.status(500).json({ error: err.message });
            }
            if (companyResult.length === 0) {
                return res.status(404).json({ error: "❌ Perusahaan tidak ditemukan!" });
            }

            const kode_perusahaan_aset = companyResult[0].kode.toUpperCase();

            // **Ambil kode jenis aset**
            db.query(`SELECT kode FROM asset_types WHERE id = ?`, [jenis_id], async (err, jenisResult) => {
                if (err) {
                    console.error("❌ Database error saat mengambil kode jenis aset:", err);
                    return res.status(500).json({ error: err.message });
                }
                if (jenisResult.length === 0) {
                    return res.status(404).json({ error: "❌ Jenis aset tidak ditemukan!" });
                }

                const kode_jenis = jenisResult[0].kode.toUpperCase();

                // **Ambil kode sub-jenis aset**
                db.query(`SELECT kode FROM asset_subtypes WHERE id = ?`, [subjenis_id], async (err, subjenisResult) => {
                    if (err) {
                        console.error("❌ Database error saat mengambil kode sub-jenis:", err);
                        return res.status(500).json({ error: err.message });
                    }
                    if (subjenisResult.length === 0) {
                        return res.status(404).json({ error: "❌ Sub-jenis aset tidak ditemukan!" });
                    }

                    const kode_subjenis = subjenisResult[0].kode.toUpperCase();


// **Ambil nomor urut terakhir berdasarkan perusahaan, subjenis & jenis aset**
db.query(
    `SELECT COALESCE(MAX(CAST(nomor_urut AS UNSIGNED)), 0) + 1 AS next_nomor_urut 
     FROM assets WHERE kode_perusahaan = ? AND jenis_id = ? AND subjenis_id = ?`,
    [company_id, jenis_id, subjenis_id],
    async (err, result) => {
        if (err) {
            console.error("❌ Database error saat mengambil nomor urut:", err);
            return res.status(500).json({ error: err.message });
        }

        let nomor_urut = result[0].next_nomor_urut;
        let nomor_urut_format = String(nomor_urut).padStart(3, "0");

        // 🔹 Generate kode aset berdasarkan format yang benar
        let kode_asset = `${kode_perusahaan_aset}${kode_departemen}${kode_lokasi}${kategori_id}${kode_jenis}${kode_subjenis}${nomor_urut_format}`;

        console.log("🔹 Kode aset yang akan dibuat:", kode_asset);

        // **Cek apakah kode aset sudah ada**
        db.query(
            `SELECT COUNT(*) AS total FROM assets WHERE kode_asset = ?`,
            [kode_asset],
            async (err, checkResult) => {
                if (err) {
                    console.error("❌ Database error saat mengecek kode aset:", err);
                    return res.status(500).json({ error: err.message });
                }
                
                if (checkResult[0].total > 0) {
                    console.error("❌ Kode aset sudah ada:", kode_asset);
                    return res.status(400).json({ error: `❌ Kode aset '${kode_asset}' sudah ada di database!` });
                }

                const qrCodeData = await QRCode.toDataURL(kode_asset);

                // **Simpan aset ke database**
                db.query(
                    `INSERT INTO assets (kode_perusahaan, kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, nomor_urut, kode_asset, deskripsi, qr_code) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [company_id, departemen_id, kode_lokasi, kategori_id, jenis_id, subjenis_id, nomor_urut, kode_asset, deskripsiFinal, qrCodeData],
                    (err, result) => {
                        if (err) {
                            console.error("❌ Gagal menambahkan aset:", err);
                            return res.status(500).json({ error: err.message });
                        }
                        res.json({ message: "✅ Aset berhasil ditambahkan!", kode_asset, qrCodeData });
                    }
                );
            }
        );
    }
);



                });
            });
        });
    });
});











//UPDATE Asset
app.put("/assets/:id", verifyToken, async (req, res) => {
    console.log("🔵 API /assets/:id [UPDATE] terpanggil!");

    const assetId = req.params.id;
    const { status } = req.body;

    if (!["active", "deleted"].includes(status)) {
        return res.status(400).json({ error: "Status tidak valid!" });
    }

    try {
        // ✅ Gunakan `con.promise().query()` agar bisa di-await
        const [result] = await db.promise().query(
            "UPDATE assets SET status = ? WHERE id = ?",
            [status, assetId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Aset tidak ditemukan!" });
        }

        console.log(`✅ Status aset ID ${assetId} berhasil diubah menjadi '${status}'`);
        res.json({ success: true, message: "Status aset berhasil diperbarui!" });

    } catch (err) {
        console.error("❌ Gagal mengupdate aset:", err);
        res.status(500).json({ error: err.message });
    }
});




//DELETE Asset (Hanya Admin)
app.delete("/assets/:id", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Hanya Admin yang dapat menghapus aset!" });
    }

    db.query(
        `DELETE FROM assets WHERE id = ?`,
        [req.params.id],
        (err, result) => {
            if (err) {
                console.error("❌ Gagal menghapus aset:", err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: "✅ Aset berhasil dihapus!" });
        }
    );
});

// ✅ API Statistik Aset (Total & Aktif)
app.get("/assets/stats", verifyToken, (req, res) => {
    const company_id = req.user.perusahaan_id;

    const query = `
        SELECT 
            COUNT(*) AS total, 
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS aktif
        FROM assets
        WHERE kode_perusahaan = ?`;

    db.query(query, [company_id], (err, results) => {
        if (err) {
            console.error("❌ Error mengambil statistik aset:", err);
            return res.status(500).json({ error: err.message });
        }

        res.json({
            total: results[0].total,
            aktif: results[0].aktif, // Hanya yang "active"
        });
    });
});





 
// ✅ GET ASSET DETAIL BY KODE (QRCODE SCAN ASET)
app.get("/assets/:kode_asset", verifyToken, (req, res) => {
    const { kode_asset } = req.params;

    console.log(`📡 Fetching asset with kode_asset: ${kode_asset}`);

    const query = `
        SELECT       
            assets.kode_asset,
            companies.kode AS kode_perusahaan,
            companies.nama_perusahaan,
            departments.nama_departments,
            locations.nama_lokasi,
            asset_types.nama_asset AS jenis_aset,
            asset_subtypes.nama_subaset AS sub_jenis_aset
        FROM assets
        LEFT JOIN companies ON assets.kode_perusahaan = companies.id
        LEFT JOIN departments ON assets.kode_departemen = departments.id
        LEFT JOIN locations ON assets.kode_lokasi = locations.id
        LEFT JOIN asset_types ON assets.jenis_id = asset_types.id
        LEFT JOIN asset_subtypes ON assets.subjenis_id = asset_subtypes.id
        WHERE assets.kode_asset = ? AND assets.status = 'active'  -- ✅ Filter only active assets
    `;

    db.query(query, [kode_asset], (err, results) => {
        if (err) {
            console.error("❌ Error fetching asset:", err);
            return res.status(500).json({ error: "Internal Server Error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: "Aset tidak ditemukan atau tidak aktif" });
        }

        console.log("✅ Data asset ditemukan:", results[0]);
        res.json(results[0]);
    });
});



  



app.post("/change-password", verifyToken, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Cari user di database
    db.query("SELECT password FROM users WHERE id = ?", [userId], (err, results) => {
        if (err || results.length === 0) return res.status(500).json({ message: "User tidak ditemukan" });

        const user = results[0];

        // Verifikasi password lama
        const passwordMatch = bcrypt.compareSync(currentPassword, user.password);
        if (!passwordMatch) return res.status(400).json({ message: "Password lama salah!" });

        // Hash password baru
        const hashedPassword = bcrypt.hashSync(newPassword, 10);

        // Update password di database
        db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, userId], (err, result) => {
            if (err) return res.status(500).json({ message: "Gagal mengganti password" });

            res.json({ message: "Password berhasil diubah! Silakan login kembali." });
        });
    });
});





// ✅ GET REPORT ASSETS (Filter Perusahaan, Departemen, Kategori, Jenis Aset)
app.get("/assets/reports", verifyToken, (req, res) => {
    console.log("📡 API /assets/reports dipanggil!");

    let { company, department, category, jenis_aset, page, limit } = req.query;

    // Pastikan filter tidak undefined
    company = company || "";
    department = department || "";
    category = category || "";
    jenis_aset = jenis_aset || "";
    page = parseInt(page) || 1;
    limit = parseInt(limit) || 10;

    let offset = (page - 1) * limit;

    console.log("🔹 Filter:", { company, department, category, jenis_aset });

    let query = `
    SELECT 
        assets.id, 
        assets.kode_asset, 
        assets.status,  
        companies.kode AS kode_perusahaan,
        companies.nama_perusahaan,
        departments.nama_departments,
        locations.nama_lokasi,
        asset_types.nama_asset AS jenis_aset,
        asset_subtypes.nama_subaset AS sub_jenis_aset,
        assets.qr_code
    FROM assets
    LEFT JOIN companies ON assets.kode_perusahaan = companies.id
    LEFT JOIN departments ON assets.kode_departemen = departments.id
    LEFT JOIN locations ON assets.kode_lokasi = locations.id
    LEFT JOIN asset_types ON assets.jenis_id = asset_types.id
    LEFT JOIN asset_subtypes ON assets.subjenis_id = asset_subtypes.id
    WHERE assets.status = 'active'
    `;

    let params = [];

    // Tambahkan filter jika tidak kosong
    if (company !== "") {
        query += " AND assets.kode_perusahaan = ?";
        params.push(company);
    }
    if (department !== "") {
        query += " AND assets.kode_departemen = ?";
        params.push(department);
    }
    if (category !== "") {
        query += " AND assets.kategori_id = ?";
        params.push(category);
    }
    if (jenis_aset !== "") {
        query += " AND assets.jenis_id = ?";
        params.push(jenis_aset);
    }
    
    // Tambahkan pagination
    query += " LIMIT ? OFFSET ?";
    params.push(limit, offset);

    console.log("🔹 Final Query:", query);
    console.log("🔹 Params:", params);

    db.query(query, params, (err, results) => {
        if (err) {
            console.error("❌ Error Query:", err);
            return res.status(500).json({ error: err.message });
        }

        res.json({
            data: results,
            totalPages: Math.ceil(results.length / limit),
            currentPage: page
        });
    });
});










// 🔹 GET USERS (Hanya Admin)
app.get("/users", verifyToken, (req, res) => {
    if (req.user.role_id !== 1) return res.status(403).json({ error: "Access Denied" });

    db.query("SELECT * FROM users", (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});


