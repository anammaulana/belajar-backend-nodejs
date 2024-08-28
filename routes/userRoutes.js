const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const router = express.Router();

// Secret key untuk JWT
const JWT_SECRET =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJhbmFtQGV4YW1wbGUuY29tIiwiaWF0IjoxNzI0ODI5OTY4LCJleHAiOjE3MjQ4MzM1Njh9.PhHLF7y2555AXdoaBuULsL0naLFSWRUMmkD6qdpedmQeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// Database sementara
let users = [];

// POST: Pendaftaran Pengguna
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Semua field wajib diisi!" });
  }

  const userExists = users.find((user) => user.email === email);
  if (userExists) {
    return res.status(400).json({ message: "Email sudah terdaftar!" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
    };
    users.push(newUser);

    res.status(201).json({
      message: "Pengguna berhasil terdaftar!",
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Terjadi kesalahan saat mendaftarkan pengguna." });
  }
});

// POST: Login Pengguna
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email dan password wajib diisi!" });
  }

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(400).json({ message: "Email atau password salah!" });
  }

  try {
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Email atau password salah!" });
    }

    // Buat JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({
      message: "Login berhasil!",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Terjadi kesalahan saat login." });
  }
});

// Middleware untuk proteksi endpoint dengan JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ message: "Akses ditolak! Token tidak ada." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token tidak valid!" });
    }
    req.user = user;
    next();
  });
};

// Contoh endpoint yang diproteksi dengan JWT
router.get("/profile", authenticateToken, (req, res) => {
  res
    .status(200)
    .json({ message: `Selamat datang, ${req.user.email}!`, user: req.user });
});

module.exports = router;
