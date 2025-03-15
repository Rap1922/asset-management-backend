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

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  })); // CORS untuk frontend

app.use(express.json()); // 🔥 Penting untuk membaca request body JSON
app.use(express.urlencoded({ extended: true })); // 🔥 Tambahkan ini untuk menangani form-data

// Cek apakah middleware berjalan
app.use((req, res, next) => {
    console.log("📝 Middleware: Request diterima dengan method", req.method, "di", req.url);
    console.log("📥 Request Body:", req.body);
    next();
});

// Koneksi ke MySQL Railway
const db = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();




db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("Connected to MySQL");
    }
});



const SECRET_KEY = process.env.SECRET_KEY;

if (!SECRET_KEY) {
    throw new Error("❌ SECRET_KEY tidak ditemukan! Pastikan sudah diset di .env.");
}


// ✅ Middleware untuk Verifikasi Token JWT
const verifyToken = (req, res, next) => {
    try {
        const authHeader = req.headers["authorization"];

        if (!authHeader) {
            return res.status(403).json({ error: "❌ Unauthorized! Token tidak ditemukan." });
        }

        const tokenParts = authHeader.split(" ");
        if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
            return res.status(401).json({ error: "❌ Format token tidak valid!" });
        }

        const token = tokenParts[1]; // Ambil token setelah "Bearer"

        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                console.error("❌ JWT Error:", err.message);
                return res.status(401).json({ error: "❌ Token tidak valid atau telah kedaluwarsa!" });
            }

            req.user = decoded; // Simpan data user yang sudah diverifikasi ke req.user
            next();
        });
    } catch (error) {
        console.error("❌ Middleware Error:", error);
        res.status(500).json({ error: "❌ Internal Server Error dalam verifikasi token" });
    }
};

module.exports = verifyToken; // ✅ Pastikan middleware bisa dipakai di file lain



// app.get("/", (req, res) => {
//     res.json({ message: "Backend API is running 🚀" });
// });

app.listen(5000, "0.0.0.0", () => {
    console.log("Server running on port 5000 and accessible via network");
});






// ✅ REGISTER USER (Dengan Validasi Email Unik & Password Minimal 6 Karakter)
// ✅ REGISTER USER (Role Default = 3)
app.post("/register", async (req, res) => {
    const { nama, email, password, perusahaan_id } = req.body;  // 🛑 role_id diatur otomatis ke 3 (Staff)

    if (password.length < 6) {
        return res.status(400).json({ error: "Password harus minimal 6 karakter" });
    }

    try {
        // Cek apakah email sudah terdaftar
        const [existingUsers] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: "Email sudah terdaftar!" });
        }

        // Hash password sebelum disimpan
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Insert user baru dengan role_id = 3 (Staff)
        await db.query(
            "INSERT INTO users (nama_user, email, password, role_id, perusahaan_id) VALUES (?, ?, ?, ?, ?)",
            [nama, email, hashedPassword, 3, perusahaan_id]
        );

        res.json({ message: "User berhasil terdaftar sebagai Staff" });
    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 LOGIN USER & GENERATE TOKEN
app.post("/login", async (req, res) => {
    const { email, password, perusahaan_id } = req.body;

    try {
        const [results] = await db.query(`
            SELECT users.id, users.nama_user, users.password, users.role_id, 
                   users.perusahaan_id, companies.nama_perusahaan
            FROM users
            JOIN companies ON users.perusahaan_id = companies.id
            WHERE users.email = ? AND users.perusahaan_id = ?
        `, [email, perusahaan_id]);

        if (results.length === 0) {
            return res.status(401).json({ error: "Email atau perusahaan tidak cocok" });
        }

        const user = results[0];

        console.log("User ditemukan di DB:", user); // Debugging

        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Password salah" });
        }

        const token = jwt.sign({
            id: user.id,
            nama_user: user.nama_user,
            perusahaan_id: user.perusahaan_id,
            nama_perusahaan: user.nama_perusahaan,
            role_id: user.role_id
        }, SECRET_KEY, { expiresIn: "2h" });

        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 GET USER BERDASARKAN ID (Hanya bisa melihat data user dalam `company_id` mereka)
app.get("/users/:id", verifyToken, async (req, res) => {
    const { id } = req.params;
    const company_id = req.user.perusahaan_id;

    try {
        const [results] = await db.query(
            "SELECT id, nama, email, role_id, perusahaan_id FROM users WHERE id = ? AND perusahaan_id = ?", 
            [id, company_id]
        );

        if (results.length === 0) {
            return res.status(404).json({ error: "User tidak ditemukan atau tidak memiliki akses" });
        }

        res.json(results[0]);
    } catch (err) {
        console.error("Error mendapatkan data user:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 GANTI PASSWORD (Hanya untuk user sendiri)
app.post("/change-password", verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        // **1️⃣ Cek apakah user ada di database**
        const [userResult] = await db.promise().query(
            "SELECT password FROM users WHERE id = ?", 
            [userId]
        );

        if (userResult.length === 0) {
            return res.status(404).json({ message: "❌ User tidak ditemukan" });
        }

        const user = userResult[0];

        // **2️⃣ Verifikasi password lama**
        const passwordMatch = bcrypt.compareSync(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: "❌ Password lama salah!" });
        }

        // **3️⃣ Hash password baru**
        const hashedPassword = bcrypt.hashSync(newPassword, 10);

        // **4️⃣ Update password di database**
        await db.promise().query(
            "UPDATE users SET password = ? WHERE id = ?", 
            [hashedPassword, userId]
        );

        res.json({ message: "✅ Password berhasil diubah! Silakan login kembali." });

    } catch (err) {
        console.error("❌ Error mengubah password:", err);
        res.status(500).json({ message: err.message });
    }
});




// 🔹 GET ALL USERS (Hanya melihat user dalam `company_id` mereka kecuali admin)
app.get("/users", verifyToken, async (req, res) => {
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

    try {
        const [results] = await db.query(query, params);
        res.json(results);
    } catch (err) {
        console.error("Error mendapatkan daftar user:", err);
        res.status(500).json({ error: err.message });
    }
});



// 🔹 ADD USER (Admin bisa menambahkan user ke perusahaan lain, user biasa hanya ke `company_id` mereka)
app.post("/users", verifyToken, async (req, res) => {
    const { nama, email, password, role_id, perusahaan_id } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    if (req.user.role_id !== 1 && perusahaan_id !== req.user.perusahaan_id) {
        return res.status(403).json({ error: "Access Denied! Tidak bisa menambahkan user ke perusahaan lain." });
    }

    try {
        await db.query(
            "INSERT INTO users (nama, email, password, role_id, perusahaan_id) VALUES (?, ?, ?, ?, ?)", 
            [nama, email, hashedPassword, role_id, perusahaan_id]
        );
        res.json({ message: "User berhasil ditambahkan" });
    } catch (err) {
        console.error("Error menambah user:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 UPDATE USER (Admin bisa edit semua user, user biasa hanya dalam `company_id` mereka)
app.put("/users/:id", verifyToken, async (req, res) => {
    const { nama, email, role_id, perusahaan_id } = req.body;

    if (req.user.role_id !== 1 && perusahaan_id !== req.user.perusahaan_id) {
        return res.status(403).json({ error: "Access Denied! Tidak bisa mengedit user dari perusahaan lain." });
    }

    try {
        const [result] = await db.query(
            "UPDATE users SET nama = ?, email = ?, role_id = ?, perusahaan_id = ? WHERE id = ?", 
            [nama, email, role_id, perusahaan_id, req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "User tidak ditemukan" });
        }

        res.json({ message: "User berhasil diperbarui" });
    } catch (err) {
        console.error("Error mengupdate user:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 DELETE USER (Admin hanya bisa menghapus user dalam `company_id` mereka)
app.delete("/users/:id", verifyToken, async (req, res) => {
    if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "Access Denied!" });
    }

    try {
        const [result] = await db.query(
            "DELETE FROM users WHERE id = ? AND perusahaan_id = ?", 
            [req.params.id, req.user.perusahaan_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "Tidak diizinkan menghapus user dari perusahaan lain!" });
        }

        res.json({ message: "User berhasil dihapus" });
    } catch (err) {
        console.error("Error menghapus user:", err);
        res.status(500).json({ error: err.message });
    }
});



// ✅ GET ROLES
app.get("/roles", verifyToken, async (req, res) => {
    try {
        const [results] = await db.promise().query("SELECT * FROM roles");
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ GET COMPANIES
app.get("/companies", async (req, res) => {
    try {
        const [results] = await db.promise().query("SELECT * FROM companies");
        console.log("Data perusahaan berhasil diambil:", results);
        res.json(results);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ ADD COMPANY
app.post("/companies", async (req, res) => {
    const { kode, nama_perusahaan } = req.body;
    try {
        await db.promise().query("INSERT INTO companies (kode, nama_perusahaan) VALUES (?, ?)", [kode, nama_perusahaan]);
        res.json({ message: "Perusahaan ditambahkan" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ UPDATE COMPANY
app.put("/companies/:id", async (req, res) => {
    const { kode, nama_perusahaan } = req.body;
    try {
        const [result] = await db.promise().query("UPDATE companies SET kode = ?, nama_perusahaan = ? WHERE id = ?", [kode, nama_perusahaan, req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: "Perusahaan tidak ditemukan" });
        res.json({ message: "Perusahaan diperbarui" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ DELETE COMPANY
app.delete("/companies/:id", async (req, res) => {
    try {
        const [result] = await db.promise().query("DELETE FROM companies WHERE id = ?", [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: "Perusahaan tidak ditemukan" });
        res.json({ message: "Perusahaan dihapus" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



// 🔹 GET COMPANIES (Untuk Form Login)
app.get("/companies/list", async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, nama_perusahaan FROM companies");
        console.log("Data perusahaan:", results); // 🔥 Debug hasil query
        res.json(results);
    } catch (err) {
        console.error("Database error:", err); // 🔥 Debug error
        res.status(500).json({ error: err.message });
    }
});






// 🔹 GET ALL DEPARTMENTS (Hanya untuk company_id yang sama dengan user)
app.get("/departments", verifyToken, async (req, res) => {
    try {
      const perusahaan_id = req.user.perusahaan_id;
      if (!perusahaan_id) {
        return res.status(400).json({ error: "Company ID not found in token" });
      }
  
      const [results] = await db.promise().query(
        "SELECT * FROM departments WHERE company_id = ? ORDER BY CAST(kode AS UNSIGNED) ASC",
        [perusahaan_id]
      );
  
      res.json(results);
    } catch (err) {
      console.error("Database error:", err);
      res.status(500).json({ error: err.message });
    }
  });
  
  // 🔹 ADD DEPARTMENT (Hanya untuk company_id user)
  app.post("/departments", verifyToken, async (req, res) => {
    try {
      const { kode, nama_departments } = req.body;
      const company_id = req.user.perusahaan_id;
  
      if (!kode || !nama_departments) {
        return res.status(400).json({ error: "Kode dan Nama Departemen wajib diisi!" });
      }
  
      await db.promise().query(
        "INSERT INTO departments (company_id, kode, nama_departments) VALUES (?, ?, ?)",
        [company_id, kode, nama_departments]
      );
  
      res.json({ message: "Departemen berhasil ditambahkan!" });
    } catch (err) {
      console.error("❌ Gagal menambahkan departemen:", err);
      res.status(500).json({ error: err.message });
    }
  });
  
  // 🔹 UPDATE DEPARTMENT (Hanya bisa edit departemen dalam company_id user)
  app.put("/departments/:id", verifyToken, async (req, res) => {
    try {
      const { kode, nama_departments } = req.body;
      const company_id = req.user.perusahaan_id;
  
      if (!kode || !nama_departments) {
        return res.status(400).json({ error: "Kode dan Nama Departemen wajib diisi!" });
      }
  
      const [result] = await db.promise().query(
        "UPDATE departments SET kode = ?, nama_departments = ? WHERE id = ? AND company_id = ?",
        [kode, nama_departments, req.params.id, company_id]
      );
  
      if (result.affectedRows === 0) {
        return res.status(403).json({ error: "❌ Tidak diizinkan mengedit departemen dari perusahaan lain!" });
      }
  
      res.json({ message: "Departemen berhasil diperbarui!" });
    } catch (err) {
      console.error("❌ Gagal memperbarui departemen:", err);
      res.status(500).json({ error: err.message });
    }
  });
  
  // 🔹 DELETE DEPARTMENT (Hanya Admin dan hanya dari company_id user)
  app.delete("/departments/:id", verifyToken, async (req, res) => {
    try {
      if (req.user.role_id !== 1) {
        return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus departemen." });
      }
  
      const company_id = req.user.perusahaan_id;
  
      const [result] = await db.promise().query(
        "DELETE FROM departments WHERE id = ? AND company_id = ?",
        [req.params.id, company_id]
      );
  
      if (result.affectedRows === 0) {
        return res.status(403).json({ error: "❌ Tidak diizinkan menghapus departemen dari perusahaan lain!" });
      }
  
      res.json({ message: "Departemen berhasil dihapus!" });
    } catch (err) {
      console.error("❌ Gagal menghapus departemen:", err);
      res.status(500).json({ error: err.message });
    }
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
app.post("/locations", verifyToken, async (req, res) => {
    try {
        console.log("Request Diterima:", req.body); 
        const { kode, nama_lokasi } = req.body;
        const company_id = req.user.perusahaan_id;

        if (!company_id) return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        if (!kode || !nama_lokasi) return res.status(400).json({ error: "Kode dan Nama Lokasi wajib diisi!" });

        const [result] = await db.promise().query(
            "INSERT INTO locations (company_id, kode, nama_lokasi) VALUES (?, ?, ?)",
            [company_id, kode, nama_lokasi]
        );

        console.log("✅ Lokasi Berhasil Ditambahkan:", result);
        res.json({ message: "Lokasi berhasil ditambahkan!" });
    } catch (err) {
        console.error("❌ Gagal menambahkan lokasi:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔹 UPDATE LOCATION
app.put("/locations/:id", verifyToken, async (req, res) => {
    try {
        const { kode, nama_lokasi } = req.body;
        const company_id = req.user.perusahaan_id;

        if (!company_id) return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        if (!kode || !nama_lokasi) return res.status(400).json({ error: "Kode dan Nama Lokasi wajib diisi!" });

        const [result] = await db.promise().query(
            "UPDATE locations SET kode = ?, nama_lokasi = ? WHERE id = ? AND company_id = ?",
            [kode, nama_lokasi, req.params.id, company_id]
        );

        if (result.affectedRows === 0) return res.status(403).json({ error: "❌ Tidak diizinkan mengedit lokasi dari perusahaan lain!" });

        console.log("✅ Lokasi Berhasil Diperbarui:", result);
        res.json({ message: "Lokasi berhasil diperbarui!" });
    } catch (err) {
        console.error("❌ Gagal memperbarui lokasi:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔹 DELETE LOCATION
app.delete("/locations/:id", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus lokasi." });
        const company_id = req.user.perusahaan_id;

        const [result] = await db.promise().query(
            "DELETE FROM locations WHERE id = ? AND company_id = ?",
            [req.params.id, company_id]
        );

        if (result.affectedRows === 0) return res.status(403).json({ error: "❌ Tidak diizinkan menghapus lokasi dari perusahaan lain!" });

        console.log("✅ Lokasi Berhasil Dihapus:", result);
        res.json({ message: "Lokasi berhasil dihapus!" });
    } catch (err) {
        console.error("❌ Gagal menghapus lokasi:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 GET ALL CATEGORIES (Hanya untuk company_id yang sama dengan user)
app.get("/categories", verifyToken, async (req, res) => {
    try {
        const company_id = req.user.perusahaan_id;
        if (!company_id) {
            return res.status(400).json({ error: "Company ID not found in token" });
        }

        console.log("Company ID dari Token:", company_id); // ✅ Debug perusahaan_id dari token

        const [results] = await db.promise().query(
            "SELECT * FROM asset_categories WHERE company_id = ? ORDER BY CAST(kode AS UNSIGNED) ASC",
            [company_id]
        );

        console.log("✅ Data Kategori Ditemukan:", results); // ✅ Debug hasil query
        res.json(results);
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔹 ADD CATEGORY (Hanya untuk company_id yang sama dengan user)
app.post("/categories", verifyToken, async (req, res) => {
    try {
        const { kode, nama_kategori } = req.body;
        const company_id = req.user.perusahaan_id;

        console.log("Company ID dari Token:", company_id, "Kategori Diterima:", req.body); // ✅ Debugging

        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }
        if (!kode || !nama_kategori) {
            return res.status(400).json({ error: "Kode dan Nama Kategori wajib diisi!" });
        }

        await db.promise().query(
            "INSERT INTO asset_categories (company_id, kode, nama_kategori) VALUES (?, ?, ?)",
            [company_id, kode, nama_kategori]
        );

        console.log("✅ Kategori Berhasil Ditambahkan");
        res.json({ message: "Kategori berhasil ditambahkan!" });
    } catch (err) {
        console.error("❌ Gagal menambahkan kategori:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔹 UPDATE CATEGORY (Hanya bisa edit kategori dalam company_id user)
app.put("/categories/:id", verifyToken, async (req, res) => {
    try {
        const { kode, nama_kategori } = req.body;
        const company_id = req.user.perusahaan_id;
        const categoryId = req.params.id;

        console.log("Company ID dari Token:", company_id, "Kategori ID:", categoryId, "Kategori Update:", req.body); // ✅ Debugging

        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }
        if (!kode || !nama_kategori) {
            return res.status(400).json({ error: "Kode dan Nama Kategori wajib diisi!" });
        }

        const [result] = await db.promise().query(
            "UPDATE asset_categories SET kode = ?, nama_kategori = ? WHERE id = ? AND company_id = ?",
            [kode, nama_kategori, categoryId, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan mengedit kategori dari perusahaan lain!" });
        }

        console.log("✅ Kategori Berhasil Diperbarui");
        res.json({ message: "Kategori berhasil diperbarui!" });
    } catch (err) {
        console.error("❌ Gagal memperbarui kategori:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔹 DELETE CATEGORY (Hanya Admin dan hanya dari company_id user)
app.delete("/categories/:id", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) {
            return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus kategori." });
        }

        const company_id = req.user.perusahaan_id;
        const categoryId = req.params.id;

        console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Kategori ID:", categoryId); // ✅ Debugging

        const [result] = await db.promise().query(
            "DELETE FROM asset_categories WHERE id = ? AND company_id = ?",
            [categoryId, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus kategori dari perusahaan lain!" });
        }

        console.log("✅ Kategori Berhasil Dihapus");
        res.json({ message: "Kategori berhasil dihapus!" });
    } catch (err) {
        console.error("❌ Gagal menghapus kategori:", err);
        res.status(500).json({ error: err.message });
    }
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
app.get("/types", verifyToken, async (req, res) => {
    try {
        const company_id = req.user.perusahaan_id;
        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }

        console.log("Company ID dari Token:", company_id);

        const [results] = await db.promise().query(
            `SELECT asset_types.* FROM asset_types 
             JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
             WHERE asset_categories.company_id = ?
             ORDER BY CAST(asset_types.kategori_id AS UNSIGNED) ASC`,
            [company_id]
        );

        console.log("✅ Data Types Ditemukan:", results);
        res.json(results);
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ error: err.message });
    }
});



// 🔹 ADD TYPE (Hanya untuk company_id yang sama dengan user)
app.post("/types", verifyToken, async (req, res) => {
    try {
        const { kategori_id, kode, nama_asset } = req.body;
        const company_id = req.user.perusahaan_id;

        console.log("Company ID dari Token:", company_id, "Kategori ID:", kategori_id, "Data Type Diterima:", req.body);

        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }

        if (!kategori_id || !kode || !nama_asset) {
            return res.status(400).json({ error: "Semua field wajib diisi!" });
        }

        // Pastikan kategori milik perusahaan yang sama
        const [category] = await db.promise().query(
            "SELECT * FROM asset_categories WHERE id = ? AND company_id = ?",
            [kategori_id, company_id]
        );

        if (category.length === 0) {
            return res.status(403).json({ error: "❌ Kategori tidak ditemukan atau tidak diizinkan!" });
        }

        await db.promise().query(
            "INSERT INTO asset_types (kategori_id, kode, nama_asset, company_id) VALUES (?, ?, ?, ?)",
            [kategori_id, kode, nama_asset, company_id]
        );

        console.log("✅ Jenis Aset Berhasil Ditambahkan");
        res.json({ message: "Jenis aset berhasil ditambahkan!" });
    } catch (err) {
        console.error("❌ Gagal menambahkan jenis aset:", err);
        res.status(500).json({ error: err.message });
    }
});




// 🔹 UPDATE TYPE (Hanya bisa edit jenis aset dalam company_id user)
app.put("/types/:id", verifyToken, async (req, res) => {
    try {
        const { kategori_id, kode, nama_asset } = req.body;
        const company_id = req.user.perusahaan_id;
        const typeId = req.params.id;

        console.log("Company ID dari Token:", company_id, "Kategori ID:", kategori_id, "Jenis ID:", typeId, "Data Update:", req.body);

        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }

        if (!kategori_id || !kode || !nama_asset) {
            return res.status(400).json({ error: "Semua field wajib diisi!" });
        }

        const [result] = await db.promise().query(
            `UPDATE asset_types 
             JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
             SET asset_types.kategori_id = ?, asset_types.kode = ?, asset_types.nama_asset = ?
             WHERE asset_types.id = ? AND asset_categories.company_id = ?`,
            [kategori_id, kode, nama_asset, typeId, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan mengedit jenis aset dari perusahaan lain!" });
        }

        console.log("✅ Jenis Aset Berhasil Diperbarui");
        res.json({ message: "Jenis aset berhasil diperbarui!" });
    } catch (err) {
        console.error("❌ Gagal memperbarui jenis aset:", err);
        res.status(500).json({ error: err.message });
    }
});


// 🔹 DELETE TYPE (Hanya Admin dan hanya dari company_id user)
app.delete("/types/:id", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) {
            return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus jenis aset." });
        }

        const company_id = req.user.perusahaan_id;
        const typeId = req.params.id;

        console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Jenis ID:", typeId);

        const [result] = await db.promise().query(
            `DELETE asset_types FROM asset_types 
             JOIN asset_categories ON asset_types.kategori_id = asset_categories.id 
             WHERE asset_types.id = ? AND asset_categories.company_id = ?`,
            [typeId, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus jenis aset dari perusahaan lain!" });
        }

        console.log("✅ Jenis Aset Berhasil Dihapus");
        res.json({ message: "Jenis aset berhasil dihapus!" });
    } catch (err) {
        console.error("❌ Gagal menghapus jenis aset:", err);
        res.status(500).json({ error: err.message });
    }
});



app.get("/subtypes", verifyToken, async (req, res) => {
    try {
        const company_id = req.user.perusahaan_id;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;

        console.log("Company ID dari Token:", company_id, "Halaman:", page, "Limit:", limit);

        if (!company_id) {
            return res.status(400).json({ error: "Company ID tidak ditemukan dalam token" });
        }

        const [results] = await db.promise().query(
            `SELECT asset_subtypes.* FROM asset_subtypes
             JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id
             WHERE asset_types.company_id = ?
             ORDER BY CAST(asset_subtypes.kode AS UNSIGNED) ASC
             LIMIT ? OFFSET ?`,
            [company_id, limit, offset]
        );

        const [[countResult]] = await db.promise().query(
            `SELECT COUNT(*) AS total FROM asset_subtypes
             JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id
             WHERE asset_types.company_id = ?`,
            [company_id]
        );

        console.log("✅ Data Subtypes Ditemukan:", results);
        res.json({
            data: results,
            total: countResult.total,
            totalPages: Math.ceil(countResult.total / limit),
            currentPage: page
        });

    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ error: err.message });
    }
});



app.post("/subtypes", verifyToken, async (req, res) => {
    try {
        const { jenis_id, kode, nama_subaset } = req.body;
        const company_id = req.user.perusahaan_id;

        console.log("📥 Data Subtype Diterima:", req.body);

        if (!company_id) {
            return res.status(400).json({ error: "❌ Company ID tidak ditemukan dalam token!" });
        }

        if (!jenis_id || !kode || !nama_subaset) {
            return res.status(400).json({ error: "❌ Semua field wajib diisi!" });
        }

        const [results] = await db.promise().query(
            `SELECT * FROM asset_types WHERE id = ? AND company_id = ?`,
            [jenis_id, company_id]
        );

        if (results.length === 0) {
            return res.status(403).json({ error: "❌ Jenis aset tidak ditemukan atau tidak diizinkan!" });
        }

        await db.promise().query(
            "INSERT INTO asset_subtypes (jenis_id, kode, nama_subaset, company_id) VALUES (?, ?, ?, ?)",
            [jenis_id, kode, nama_subaset, company_id]
        );

        console.log("✅ Sub-jenis berhasil ditambahkan!");
        res.json({ message: "Sub-jenis berhasil ditambahkan!" });

    } catch (err) {
        console.error("❌ Gagal menambah sub-jenis:", err);
        res.status(500).json({ error: err.message });
    }
});




app.put("/subtypes/:id", verifyToken, async (req, res) => {
    try {
        const { jenis_id, kode, nama_subaset } = req.body;
        const company_id = req.user.perusahaan_id;
        const subtype_id = req.params.id;

        if (!jenis_id || !kode || !nama_subaset) {
            return res.status(400).json({ error: "❌ Semua field wajib diisi!" });
        }

        const [result] = await db.promise().query(
            `UPDATE asset_subtypes 
             JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id 
             SET asset_subtypes.jenis_id = ?, asset_subtypes.kode = ?, asset_subtypes.nama_subaset = ?
             WHERE asset_subtypes.id = ? AND asset_types.company_id = ?`,
            [jenis_id, kode, nama_subaset, subtype_id, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan mengedit sub-jenis dari perusahaan lain!" });
        }

        console.log("✅ Sub-jenis berhasil diperbarui!");
        res.json({ message: "Sub-jenis berhasil diperbarui!" });

    } catch (err) {
        console.error("❌ Gagal memperbarui sub-jenis:", err);
        res.status(500).json({ error: err.message });
    }
});



app.delete("/subtypes/:id", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) {
            return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang bisa menghapus sub-jenis aset." });
        }

        const company_id = req.user.perusahaan_id;
        const subtype_id = req.params.id;

        console.log("Admin ID:", req.user.id, "Company ID dari Token:", company_id, "Subtype ID:", subtype_id);

        const [result] = await db.promise().query(
            `DELETE asset_subtypes FROM asset_subtypes 
             JOIN asset_types ON asset_subtypes.jenis_id = asset_types.id 
             WHERE asset_subtypes.id = ? AND asset_types.company_id = ?`,
            [subtype_id, company_id]
        );

        if (result.affectedRows === 0) {
            return res.status(403).json({ error: "❌ Tidak diizinkan menghapus sub-jenis aset dari perusahaan lain!" });
        }

        console.log("✅ Sub-Jenis Aset Berhasil Dihapus!");
        res.json({ message: "Sub-jenis aset berhasil dihapus!" });

    } catch (err) {
        console.error("❌ Gagal menghapus sub-jenis aset:", err);
        res.status(500).json({ error: err.message });
    }
});




app.get("/assets", verifyToken, async (req, res) => {
    try {
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
            LEFT JOIN asset_subtypes ON assets.subjenis_id = asset_subtypes.id 
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

        // ✅ Ambil data aset
        const [results] = await db.promise().query(query, params);

        // ✅ Ambil total aset berdasarkan filter status
        let countQuery = "SELECT COUNT(*) AS total FROM assets WHERE status = ?";
        let countParams = [status];

        if (role_id !== 1) {
            countQuery += " AND kode_perusahaan = ?";
            countParams.push(perusahaan_id);
        }

        const [[countResult]] = await db.promise().query(countQuery, countParams);

        console.log("✅ Data yang dikirim ke frontend:", JSON.stringify(results, null, 2));

        res.json({
            data: results || [], // Data aset
            total: countResult.total, // Total data
            totalPages: Math.ceil(countResult.total / limit),
            currentPage: page
        });

    } catch (err) {
        console.error("❌ Error saat mengambil data aset:", err);
        res.status(500).json({ error: err.message });
    }
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
    try {
        console.log("🔍 Data yang diterima dari frontend:", req.body);

        const { kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, deskripsi } = req.body;
        const company_id = req.user.perusahaan_id;

        // **Validasi awal**
        if (!company_id || !kode_departemen || !kode_lokasi || !kategori_id || !jenis_id || !subjenis_id) {
            return res.status(400).json({ error: "❌ Semua field kecuali deskripsi wajib diisi!" });
        }

        const deskripsiFinal = deskripsi && deskripsi.trim() !== "" ? deskripsi : null;

        // **Ambil ID departemen dari database**
        const [deptResult] = await db.promise().query(
            `SELECT id FROM departments WHERE kode = ? AND company_id = ?`,
            [kode_departemen, company_id]
        );

        if (deptResult.length === 0) {
            return res.status(404).json({ error: "❌ Departemen tidak ditemukan!" });
        }
        const departemen_id = deptResult[0].id; // Ambil ID departemen

        // **Ambil kode perusahaan**
        const [companyResult] = await db.promise().query(
            `SELECT kode FROM companies WHERE id = ?`,
            [company_id]
        );

        if (companyResult.length === 0) {
            return res.status(404).json({ error: "❌ Perusahaan tidak ditemukan!" });
        }
        const kode_perusahaan_aset = companyResult[0].kode.toUpperCase();

        // **Ambil kode jenis aset**
        const [jenisResult] = await db.promise().query(
            `SELECT kode FROM asset_types WHERE id = ?`,
            [jenis_id]
        );

        if (jenisResult.length === 0) {
            return res.status(404).json({ error: "❌ Jenis aset tidak ditemukan!" });
        }
        const kode_jenis = jenisResult[0].kode.toUpperCase();

        // **Ambil kode sub-jenis aset**
        const [subjenisResult] = await db.promise().query(
            `SELECT kode FROM asset_subtypes WHERE id = ?`,
            [subjenis_id]
        );

        if (subjenisResult.length === 0) {
            return res.status(404).json({ error: "❌ Sub-jenis aset tidak ditemukan!" });
        }
        const kode_subjenis = subjenisResult[0].kode.toUpperCase();

        // **Ambil nomor urut terakhir berdasarkan perusahaan, subjenis & jenis aset**
        const [urutResult] = await db.promise().query(
            `SELECT COALESCE(MAX(CAST(nomor_urut AS UNSIGNED)), 0) + 1 AS next_nomor_urut 
             FROM assets WHERE kode_perusahaan = ? AND jenis_id = ? AND subjenis_id = ?`,
            [company_id, jenis_id, subjenis_id]
        );

        let nomor_urut = urutResult[0].next_nomor_urut;
        let nomor_urut_format = String(nomor_urut).padStart(3, "0");

        // 🔹 Generate kode aset berdasarkan format yang benar
        let kode_asset = `${kode_perusahaan_aset}${kode_departemen}${kode_lokasi}${kategori_id}${kode_jenis}${kode_subjenis}${nomor_urut_format}`;

        console.log("🔹 Kode aset yang akan dibuat:", kode_asset);

        // **Cek apakah kode aset sudah ada**
        const [checkResult] = await db.promise().query(
            `SELECT COUNT(*) AS total FROM assets WHERE kode_asset = ?`,
            [kode_asset]
        );

        if (checkResult[0].total > 0) {
            console.error("❌ Kode aset sudah ada:", kode_asset);
            return res.status(400).json({ error: `❌ Kode aset '${kode_asset}' sudah ada di database!` });
        }

        // **Generate QR Code untuk kode aset**
        const qrCodeData = await QRCode.toDataURL(kode_asset);

        // **Simpan aset ke database**
        await db.promise().query(
            `INSERT INTO assets (kode_perusahaan, kode_departemen, kode_lokasi, kategori_id, jenis_id, subjenis_id, nomor_urut, kode_asset, deskripsi, qr_code) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, departemen_id, kode_lokasi, kategori_id, jenis_id, subjenis_id, nomor_urut, kode_asset, deskripsiFinal, qrCodeData]
        );

        res.json({ message: "✅ Aset berhasil ditambahkan!", kode_asset, qrCodeData });

    } catch (err) {
        console.error("❌ Error saat menambahkan aset:", err);
        res.status(500).json({ error: err.message });
    }
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




// ✅ DELETE ASSET (Hanya Admin)
app.delete("/assets/:id", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) {
            return res.status(403).json({ error: "❌ Hanya Admin yang dapat menghapus aset!" });
        }

        const [result] = await db.promise().query(
            `DELETE FROM assets WHERE id = ?`,
            [req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "❌ Aset tidak ditemukan!" });
        }

        res.json({ message: "✅ Aset berhasil dihapus!" });
    } catch (err) {
        console.error("❌ Gagal menghapus aset:", err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ API Statistik Aset (Total & Aktif)
app.get("/assets/stats", verifyToken, async (req, res) => {
    try {
        const company_id = req.user.perusahaan_id;

        const [results] = await db.promise().query(
            `SELECT COUNT(*) AS total, 
                    SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS aktif
             FROM assets
             WHERE kode_perusahaan = ?`,
            [company_id]
        );

        res.json({
            total: results[0].total,
            aktif: results[0].aktif || 0, // Pastikan tidak undefined/null
        });
    } catch (err) {
        console.error("❌ Error mengambil statistik aset:", err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ GET ASSET DETAIL BY KODE (QRCODE SCAN ASET)
app.get("/assets/:kode_asset", verifyToken, async (req, res) => {
    try {
        const { kode_asset } = req.params;
        console.log(`📡 Fetching asset with kode_asset: ${kode_asset}`);

        const [results] = await db.promise().query(
            `SELECT       
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
            WHERE assets.kode_asset = ? 
            AND assets.status = 'active'`, // ✅ Hanya ambil aset aktif
            [kode_asset]
        );

        if (results.length === 0) {
            return res.status(404).json({ error: "❌ Aset tidak ditemukan atau tidak aktif!" });
        }

        console.log("✅ Data asset ditemukan:", results[0]);
        res.json(results[0]);
    } catch (err) {
        console.error("❌ Error fetching asset:", err);
        res.status(500).json({ error: "❌ Internal Server Error" });
    }
});




// ✅ GET REPORT ASSETS (Filter Perusahaan, Departemen, Kategori, Jenis Aset)
app.get("/assets/reports", verifyToken, async (req, res) => {
    try {
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
        
        // Tambahkan sorting & pagination
        query += " ORDER BY assets.id DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);

        console.log("🔹 Final Query:", query);
        console.log("🔹 Params:", params);

        const [results] = await db.promise().query(query, params);

        // Ambil total data
        const [countResults] = await db.promise().query(
            `SELECT COUNT(*) AS total FROM assets WHERE status = 'active'`
        );

        res.json({
            data: results,
            total: countResults[0].total,
            totalPages: Math.ceil(countResults[0].total / limit),
            currentPage: page
        });
    } catch (err) {
        console.error("❌ Error Query:", err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ GET USERS (Hanya Admin)
app.get("/users", verifyToken, async (req, res) => {
    try {
        if (req.user.role_id !== 1) {
            return res.status(403).json({ error: "❌ Access Denied! Hanya admin yang dapat melihat daftar user." });
        }

        const [results] = await db.promise().query("SELECT id, nama, email, role_id, perusahaan_id FROM users");

        res.json(results);
    } catch (err) {
        console.error("❌ Error mengambil data user:", err);
        res.status(500).json({ error: err.message });
    }
});



